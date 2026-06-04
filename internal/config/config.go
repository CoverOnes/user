// Package config handles environment-first configuration loading.
package config

import (
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/spf13/viper"
)

// schemaNameRe validates that a Postgres schema name only contains safe characters
// to prevent SQL injection when the name is interpolated into CREATE SCHEMA.
// First character must be a letter or underscore (leading digits are invalid PG identifiers).
var schemaNameRe = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)

// minEventHMACSecretLen is the minimum accepted length for EVENT_HMAC_SECRET.
// A 32-byte secret matches the SHA-256 block/output size and resists brute force.
const minEventHMACSecretLen = 32

// piiKeyBytes is the required decoded length of USER_PII_ENCRYPTION_KEY (AES-256).
const piiKeyBytes = 32

// Config holds all configuration for the user service.
type Config struct {
	// Server
	Port int `mapstructure:"port"`

	// Postgres
	PostgresDSN string `mapstructure:"postgres_dsn"`

	// PostgresSchema is the optional Postgres schema to use (default: "" = public).
	// Set to "user" when sharing one Aiven database across multiple services
	// so each service is isolated by schema rather than by database.
	// Only alphanumeric characters and underscores are allowed ([a-zA-Z0-9_]+).
	PostgresSchema string `mapstructure:"postgres_schema"`

	// DBMaxConns is the maximum number of connections in the pgxpool (default 10).
	// Set USER_DB_MAX_CONNS to a lower value when multiple services share a small
	// Aiven plan to avoid exhausting the server's max_connections.
	DBMaxConns int `mapstructure:"db_max_conns"`

	// DBMinConns is the minimum number of idle connections in the pgxpool (default 2).
	// Set USER_DB_MIN_CONNS to 0 or 1 to reduce idle connection overhead on shared plans.
	DBMinConns int `mapstructure:"db_min_conns"`

	// Redis
	RedisURL string `mapstructure:"redis_url"`

	// JWT
	JWTPrivateKey    string `mapstructure:"jwt_private_key"`     // base64 32-byte Ed25519 seed
	JWTPrivateKeyPEM string `mapstructure:"jwt_private_key_pem"` // PKCS8 PEM alternative

	// EventHMACSecret is the shared secret used to authenticate inbound Redis events
	// (kyc.tier_changed). Read from the UN-prefixed EVENT_HMAC_SECRET so both the kyc
	// publisher and this consumer use the identical variable name. Must match the kyc
	// publisher's value. Required (≥32 chars) in non-development environments; an
	// unsigned/forged event is dropped.
	EventHMACSecret string `mapstructure:"event_hmac_secret"`

	// Access token TTL in seconds (default 600)
	AccessTokenTTLSec int `mapstructure:"access_token_ttl_sec"`

	// Refresh token TTL in hours (default 24)
	RefreshTokenTTLHours int `mapstructure:"refresh_token_ttl_hours"`

	// PIIEncryptionKey is the base64-encoded AES-256 key (must decode to exactly
	// 32 bytes) used to encrypt HIGH-sensitivity PII columns (legal_name_enc,
	// national_id_enc). Sourced from USER_PII_ENCRYPTION_KEY. Required outside
	// development (validateCore fail-fast); in dev a documented dev-default key is
	// required so the encrypt path always runs (never plaintext, even in dev).
	PIIEncryptionKey string `mapstructure:"pii_encryption_key"`

	// SMTP settings for the verification mailer (USER_SMTP_*).
	SMTPHost     string `mapstructure:"smtp_host"`
	SMTPPort     int    `mapstructure:"smtp_port"`
	SMTPUsername string `mapstructure:"smtp_username"`
	SMTPPassword string `mapstructure:"smtp_password"`
	SMTPFrom     string `mapstructure:"smtp_from"`

	// AppBaseURL is the public frontend base URL used to build the clickable
	// email-verification link (<AppBaseURL>/verify-email?token=<token>) in the
	// verification mail. Sourced from USER_APP_BASE_URL; defaults to the dev
	// frontend origin (http://localhost:5500) when unset. The trailing slash (if
	// any) is trimmed at the mailer call site so the joined path is well-formed.
	AppBaseURL string `mapstructure:"app_base_url"`

	// MFAEnforced is the RESERVED flag for the future login-enforcement step
	// (Increment 3+): when true, a later increment will require a TOTP challenge in
	// the login flow for mfa-enabled users. It is sourced from USER_MFA_ENFORCED and
	// defaults to false. NOTHING acts on it in the current increment — login is
	// deliberately left unchanged; this field only carries the configured value so
	// the enforcement step can read it without a config change.
	MFAEnforced bool `mapstructure:"mfa_enforced"`

	// TOTPIssuer is the issuer label embedded in the otpauth:// provisioning URI and
	// shown by authenticator apps (e.g. Google Authenticator). Sourced from
	// USER_TOTP_ISSUER; defaults to "CoverOnes". Must be non-empty and must NOT
	// contain a colon (the otpauth label uses "<issuer>:<account>" so a colon in the
	// issuer would corrupt the label).
	TOTPIssuer string `mapstructure:"totp_issuer"`

	// Log level: DEBUG, INFO, WARN, ERROR
	LogLevel string `mapstructure:"log_level"`

	// Environment: development | production
	Env string `mapstructure:"env"`
}

// Load reads configuration from environment variables (prefix USER_).
// Optional .env file is loaded only in non-production environments.
func Load() (*Config, error) {
	v := viper.New()

	// ENV-FIRST: set prefix and auto-bind env vars.
	v.SetEnvPrefix("USER")
	v.AutomaticEnv()
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	// Explicit BindEnv for every key to guarantee resolution.
	// NOTE: event_hmac_secret intentionally binds the UN-prefixed EVENT_HMAC_SECRET
	// (not USER_EVENT_HMAC_SECRET): it is a shared event-bus secret that BOTH the kyc
	// publisher and this consumer must read from the identical variable name. A
	// user-prefixed name would let an operator set two different values and silently
	// drop every KYC tier-promotion event. The explicit BindEnv overrides the
	// USER-prefixed AutomaticEnv lookup for this key.
	//nolint:gosec // G101: map values are environment-variable NAMES (e.g. EVENT_HMAC_SECRET / USER_JWT_PRIVATE_KEY), not hardcoded credential values
	bindings := map[string]string{
		"port":                    "USER_PORT",
		"postgres_dsn":            "USER_POSTGRES_DSN",
		"postgres_schema":         "USER_DB_SCHEMA",
		"db_max_conns":            "USER_DB_MAX_CONNS",
		"db_min_conns":            "USER_DB_MIN_CONNS",
		"redis_url":               "USER_REDIS_URL",
		"jwt_private_key":         "USER_JWT_PRIVATE_KEY",
		"jwt_private_key_pem":     "USER_JWT_PRIVATE_KEY_PEM",
		"event_hmac_secret":       "EVENT_HMAC_SECRET",
		"pii_encryption_key":      "USER_PII_ENCRYPTION_KEY",
		"smtp_host":               "USER_SMTP_HOST",
		"smtp_port":               "USER_SMTP_PORT",
		"smtp_username":           "USER_SMTP_USERNAME",
		"smtp_password":           "USER_SMTP_PASSWORD",
		"smtp_from":               "USER_SMTP_FROM",
		"app_base_url":            "USER_APP_BASE_URL",
		"access_token_ttl_sec":    "USER_ACCESS_TOKEN_TTL_SEC",
		"refresh_token_ttl_hours": "USER_REFRESH_TOKEN_TTL_HOURS",
		"mfa_enforced":            "USER_MFA_ENFORCED",
		"totp_issuer":             "USER_TOTP_ISSUER",
		"log_level":               "USER_LOG_LEVEL",
		"env":                     "USER_ENV",
	}
	for key, envKey := range bindings {
		if err := v.BindEnv(key, envKey); err != nil {
			return nil, fmt.Errorf("config bind %q: %w", key, err)
		}
	}

	// Defaults.
	v.SetDefault("port", 8080)
	v.SetDefault("access_token_ttl_sec", 600)
	v.SetDefault("refresh_token_ttl_hours", 24)
	v.SetDefault("log_level", "INFO")
	v.SetDefault("env", "development")
	v.SetDefault("db_max_conns", 10)
	v.SetDefault("db_min_conns", 2)
	v.SetDefault("smtp_port", 587)
	v.SetDefault("app_base_url", "http://localhost:5500")
	v.SetDefault("mfa_enforced", false)
	v.SetDefault("totp_issuer", "CoverOnes")

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("unmarshal config: %w", err)
	}

	if err := cfg.validate(); err != nil {
		return nil, err
	}

	return &cfg, nil
}

func (c *Config) validate() error {
	errs := c.validateCore()
	errs = append(errs, c.validateDB()...)

	if len(errs) > 0 {
		return errors.New("config validation failed: " + strings.Join(errs, "; "))
	}

	return nil
}

// validateCore checks server, JWT, and token TTL fields.
func (c *Config) validateCore() []string {
	var errs []string

	if c.PostgresDSN == "" {
		errs = append(errs, "USER_POSTGRES_DSN is required")
	}
	if c.Port <= 0 || c.Port > 65535 {
		errs = append(errs, "USER_PORT must be 1-65535")
	}
	if c.AccessTokenTTLSec <= 0 || c.AccessTokenTTLSec > 3600 {
		errs = append(errs, "USER_ACCESS_TOKEN_TTL_SEC must be 1-3600")
	}
	if c.RefreshTokenTTLHours <= 0 || c.RefreshTokenTTLHours > 720 {
		errs = append(errs, "USER_REFRESH_TOKEN_TTL_HOURS must be 1-720")
	}

	validLogLevels := map[string]bool{"DEBUG": true, "INFO": true, "WARN": true, "ERROR": true}
	if !validLogLevels[strings.ToUpper(c.LogLevel)] {
		errs = append(errs, "USER_LOG_LEVEL must be DEBUG|INFO|WARN|ERROR")
	}

	// F13: In production, an explicit Ed25519 private key MUST be configured.
	// Ephemeral keys are only acceptable in development (tokens don't survive restarts).
	if strings.EqualFold(c.Env, "production") &&
		c.JWTPrivateKey == "" && c.JWTPrivateKeyPEM == "" {
		errs = append(errs, "USER_JWT_PRIVATE_KEY or USER_JWT_PRIVATE_KEY_PEM is required in production")
	}

	// P0: outside development, the event HMAC secret MUST be present and ≥32 chars.
	// Without it, inbound kyc.tier_changed events cannot be authenticated and a
	// forged Redis publish could elevate any user to Tier2. In development we allow
	// an empty secret (the consumer then drops all signed events — fail-closed).
	if !c.IsDev() {
		if c.EventHMACSecret == "" {
			errs = append(errs, "EVENT_HMAC_SECRET is required outside development")
		} else if len(c.EventHMACSecret) < minEventHMACSecretLen {
			errs = append(errs, "EVENT_HMAC_SECRET must be at least 32 characters")
		}
	}

	errs = append(errs, c.validatePIIAndSMTP()...)
	errs = append(errs, c.validateMFA()...)

	return errs
}

// validateMFA checks the TOTP 2FA settings. The issuer is embedded into the otpauth
// "<issuer>:<account>" label, so an empty issuer or one containing a colon would
// corrupt the provisioning URI parsed by authenticator apps. MFAEnforced is a plain
// bool (no validation needed) and is intentionally NOT acted on this increment.
func (c *Config) validateMFA() []string {
	var errs []string

	if strings.TrimSpace(c.TOTPIssuer) == "" {
		errs = append(errs, "USER_TOTP_ISSUER must not be empty")
	} else if strings.Contains(c.TOTPIssuer, ":") {
		errs = append(errs, "USER_TOTP_ISSUER must not contain a colon")
	}

	return errs
}

// validatePIIAndSMTP fail-fasts on the PII encryption key and SMTP settings.
//
// PII key (mirrors kyc config.go:151): the legal_name / national_id columns are
// always encrypted — there is NO plaintext fallback, even in dev — so a usable
// key is required in EVERY environment. Outside dev it must additionally decode to
// exactly 32 bytes. In dev a documented dev-default key (see .env.example) keeps
// the encrypt path exercised locally.
//
// SMTP: non-dev requires USER_SMTP_HOST so verification mail can actually be sent.
func (c *Config) validatePIIAndSMTP() []string {
	var errs []string

	if c.PIIEncryptionKey == "" {
		errs = append(errs,
			"USER_PII_ENCRYPTION_KEY is required when USER_ENV != development "+
				"(and a documented dev-default key is required in development): "+
				"legal_name/national_id are encrypted with no plaintext fallback "+
				"(generate with: openssl rand -base64 32)")
	} else if !c.IsDev() {
		// Non-dev: the key MUST decode to exactly 32 bytes (AES-256). In dev we skip
		// the strict length check so a short documented dev key still boots.
		key, decErr := base64.StdEncoding.DecodeString(c.PIIEncryptionKey)
		if decErr != nil || len(key) != piiKeyBytes {
			errs = append(errs,
				fmt.Sprintf("USER_PII_ENCRYPTION_KEY must be base64 that decodes to exactly %d bytes", piiKeyBytes))
		}
	}

	if !c.IsDev() && c.SMTPHost == "" {
		errs = append(errs, "USER_SMTP_HOST is required when USER_ENV != development")
	}

	return errs
}

// validateDB checks Postgres schema and connection-pool sizing fields.
func (c *Config) validateDB() []string {
	var errs []string

	if c.PostgresSchema != "" && !schemaNameRe.MatchString(c.PostgresSchema) {
		errs = append(errs, "USER_DB_SCHEMA must start with a letter or underscore and contain only [a-zA-Z0-9_] characters")
	}

	if c.DBMaxConns < 0 || c.DBMaxConns > 1000 {
		errs = append(errs, "USER_DB_MAX_CONNS must be 0-1000 (0 = use default of 10)")
	}

	if c.DBMinConns < 0 || c.DBMinConns > 1000 {
		errs = append(errs, "USER_DB_MIN_CONNS must be 0-1000 (0 = use default of 2)")
	}

	return errs
}

// IsDev reports whether the service is running in development mode.
func (c *Config) IsDev() bool {
	return c.Env == "development"
}
