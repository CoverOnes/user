// Package config handles environment-first configuration loading.
package config

import (
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/joho/godotenv"
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

// devEventHMACSecret is the publicly-known dev-default value of EVENT_HMAC_SECRET.
// Any non-dev deployment that boots with this value uses a compromised HMAC key.
//
//nolint:gosec // G101: this constant is the known-bad value being BLOCKED, not a real credential.
const devEventHMACSecret = "dev-shared-event-hmac-secret-min32-0123456789"

// devPIIEncryptionKey is the publicly-known dev-default value of USER_PII_ENCRYPTION_KEY.
// Any non-dev deployment that boots with this value encrypts PII with a compromised key.
const devPIIEncryptionKey = "Y292ZXJvbmVzLWRldi1waWkta2V5LTMyYnl0ZXNsZW4="

// mailerBackendComms is the USER_MAILER_BACKEND value that delegates email to the
// notification comms service rather than SMTP-sending directly.
const mailerBackendComms = "comms"

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
	// verification mail. Sourced from USER_APP_BASE_URL.
	AppBaseURL string `mapstructure:"app_base_url"`

	// MailerBackend selects the verification email transport: "smtp" (default)
	// uses the SMTPMailer directly; "comms" delegates to the notification
	// comms service. Sourced from USER_MAILER_BACKEND.
	MailerBackend string `mapstructure:"mailer_backend"`

	// CommsBaseURL is the internal base URL of the notification comms service
	// (e.g. http://notification:8084 inside the Docker network).
	// Required when MailerBackend="comms". Sourced from USER_COMMS_BASE_URL.
	CommsBaseURL string `mapstructure:"comms_base_url"`

	// CommsS2SToken is the shared bearer token for the S2S comms send API
	// (X-Service-Token header). Required when MailerBackend="comms".
	// Sourced from USER_COMMS_S2S_TOKEN (env-only, never committed).
	CommsS2SToken string `mapstructure:"comms_s2s_token"`

	// GatewayHMACSecret is the shared secret used to verify the gateway-origin
	// identity signature (conventions §24.1). It MUST equal the gateway's
	// GATEWAY_HMAC_SECRET. Non-dev (production/staging) fails fast at boot if
	// empty or shorter than 32 chars; development may omit it (verification
	// disabled, mirroring the gateway which also disables signing in dev).
	// Env: USER_GATEWAY_HMAC_SECRET
	GatewayHMACSecret string `mapstructure:"gateway_hmac_secret"`

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

	// UserRateLimitPerMin is the sustained per-authenticated-user request rate for the
	// /v1/me group (tokens per minute). Set USER_USER_RATE_LIMIT_PER_MIN to 0 to
	// disable the limiter entirely (useful in tests or environments that rate-limit
	// at the gateway layer instead). Default: 120.
	UserRateLimitPerMin int `mapstructure:"user_rate_limit_per_min"`

	// UserRateLimitBurst is the maximum burst size for the per-user /v1/me limiter.
	// Sourced from USER_USER_RATE_LIMIT_BURST. Default: 20.
	UserRateLimitBurst int `mapstructure:"user_rate_limit_burst"`

	// OAuthGoogleClientID / OAuthGoogleClientSecret are the Google OIDC app credentials.
	// Required when OAuth is enabled (USER_OAUTH_GOOGLE_CLIENT_ID != "").
	OAuthGoogleClientID     string `mapstructure:"oauth_google_client_id"`
	OAuthGoogleClientSecret string `mapstructure:"oauth_google_client_secret"`

	// OAuthLINEChannelID / OAuthLINEChannelSecret are the LINE Login v2.1 credentials.
	// Required when OAuth is enabled (USER_OAUTH_LINE_CHANNEL_ID != "").
	OAuthLINEChannelID     string `mapstructure:"oauth_line_channel_id"`
	OAuthLINEChannelSecret string `mapstructure:"oauth_line_channel_secret"`

	// OAuthRedirectBaseURL is the public base URL used to build per-provider redirect URIs
	// (e.g. https://api.example.com). Required when any OAuth provider is configured.
	OAuthRedirectBaseURL string `mapstructure:"oauth_redirect_base_url"`

	// OAuthFrontendPostLoginURL is the frontend URL the callback redirects to after
	// OAuth login (success: ?code=<onetime>, collision: ?error=email_exists).
	// Required when any OAuth provider is configured.
	OAuthFrontendPostLoginURL string `mapstructure:"oauth_frontend_post_login_url"`

	// OAuthStateHMACSecret is the HMAC secret used to sign OAuth state parameters
	// (anti-CSRF). Required when any OAuth provider is configured. ≥32 chars.
	OAuthStateHMACSecret string `mapstructure:"oauth_state_hmac_secret"`

	// Log level: DEBUG, INFO, WARN, ERROR
	LogLevel string `mapstructure:"log_level"`

	// Environment: development | production
	Env string `mapstructure:"env"`
}

// Load reads configuration from environment variables (prefix USER_).
// Before viper binding, .env.local and .env files are loaded via godotenv so
// local-dev configuration can be supplied without environment injection.
// Errors are silently ignored — the files are optional and godotenv does NOT
// override variables that are already set in the process environment, so
// injected-by-Docker / injected-by-k8s env always wins.
// Convention: .env = production-ish defaults (committed as .env.example only);
// .env.local = developer-local overrides (gitignored).
func Load() (*Config, error) {
	// Load .env.local first (highest priority), then .env as fallback.
	// Both are optional; missing files are not an error.
	_ = godotenv.Load(".env.local")
	_ = godotenv.Load(".env")

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
		"port":                          "USER_PORT",
		"postgres_dsn":                  "USER_POSTGRES_DSN",
		"postgres_schema":               "USER_DB_SCHEMA",
		"db_max_conns":                  "USER_DB_MAX_CONNS",
		"db_min_conns":                  "USER_DB_MIN_CONNS",
		"redis_url":                     "USER_REDIS_URL",
		"jwt_private_key":               "USER_JWT_PRIVATE_KEY",
		"jwt_private_key_pem":           "USER_JWT_PRIVATE_KEY_PEM",
		"event_hmac_secret":             "EVENT_HMAC_SECRET",
		"gateway_hmac_secret":           "USER_GATEWAY_HMAC_SECRET",
		"pii_encryption_key":            "USER_PII_ENCRYPTION_KEY",
		"smtp_host":                     "USER_SMTP_HOST",
		"smtp_port":                     "USER_SMTP_PORT",
		"smtp_username":                 "USER_SMTP_USERNAME",
		"smtp_password":                 "USER_SMTP_PASSWORD",
		"smtp_from":                     "USER_SMTP_FROM",
		"app_base_url":                  "USER_APP_BASE_URL",
		"mailer_backend":                "USER_MAILER_BACKEND",
		"comms_base_url":                "USER_COMMS_BASE_URL",
		"comms_s2s_token":               "USER_COMMS_S2S_TOKEN",
		"access_token_ttl_sec":          "USER_ACCESS_TOKEN_TTL_SEC",
		"refresh_token_ttl_hours":       "USER_REFRESH_TOKEN_TTL_HOURS",
		"mfa_enforced":                  "USER_MFA_ENFORCED",
		"totp_issuer":                   "USER_TOTP_ISSUER",
		"user_rate_limit_per_min":       "USER_USER_RATE_LIMIT_PER_MIN",
		"user_rate_limit_burst":         "USER_USER_RATE_LIMIT_BURST",
		"oauth_google_client_id":        "USER_OAUTH_GOOGLE_CLIENT_ID",
		"oauth_google_client_secret":    "USER_OAUTH_GOOGLE_CLIENT_SECRET",
		"oauth_line_channel_id":         "USER_OAUTH_LINE_CHANNEL_ID",
		"oauth_line_channel_secret":     "USER_OAUTH_LINE_CHANNEL_SECRET",
		"oauth_redirect_base_url":       "USER_OAUTH_REDIRECT_BASE_URL",
		"oauth_frontend_post_login_url": "USER_OAUTH_FRONTEND_POST_LOGIN_URL",
		"oauth_state_hmac_secret":       "USER_OAUTH_STATE_HMAC_SECRET",
		"log_level":                     "USER_LOG_LEVEL",
		"env":                           "USER_ENV",
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
	v.SetDefault("mailer_backend", "smtp")
	v.SetDefault("mfa_enforced", false)
	v.SetDefault("totp_issuer", "CoverOnes")
	v.SetDefault("user_rate_limit_per_min", 120)
	v.SetDefault("user_rate_limit_burst", 20)

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
	errs = append(errs, c.validateUserRateLimit()...)
	errs = append(errs, c.validateOAuth()...)

	if len(errs) > 0 {
		return errors.New("config validation failed: " + strings.Join(errs, "; "))
	}

	return nil
}

// minOAuthHMACSecretLen is the minimum length of the OAuth state HMAC secret.
const minOAuthHMACSecretLen = 32

// validateOAuth checks OAuth provider credentials when any provider is configured.
// OAuth is considered "enabled" when any of the provider credential fields is set.
// When enabled, the shared fields (redirect URL, frontend URL, HMAC secret) are required.
func (c *Config) validateOAuth() []string {
	googleEnabled := c.OAuthGoogleClientID != ""
	lineEnabled := c.OAuthLINEChannelID != ""

	if !googleEnabled && !lineEnabled {
		// OAuth disabled — no validation needed.
		return nil
	}

	var errs []string

	if googleEnabled && c.OAuthGoogleClientSecret == "" {
		errs = append(errs, "USER_OAUTH_GOOGLE_CLIENT_SECRET is required when USER_OAUTH_GOOGLE_CLIENT_ID is set")
	}

	if lineEnabled && c.OAuthLINEChannelSecret == "" {
		errs = append(errs, "USER_OAUTH_LINE_CHANNEL_SECRET is required when USER_OAUTH_LINE_CHANNEL_ID is set")
	}

	if strings.TrimSpace(c.OAuthRedirectBaseURL) == "" {
		errs = append(errs, "USER_OAUTH_REDIRECT_BASE_URL is required when any OAuth provider is configured")
	} else if !c.IsDev() && !strings.HasPrefix(c.OAuthRedirectBaseURL, "https://") {
		errs = append(errs, "USER_OAUTH_REDIRECT_BASE_URL must start with https:// in non-dev environments")
	}

	if strings.TrimSpace(c.OAuthFrontendPostLoginURL) == "" {
		errs = append(errs, "USER_OAUTH_FRONTEND_POST_LOGIN_URL is required when any OAuth provider is configured")
	} else if !c.IsDev() && !strings.HasPrefix(c.OAuthFrontendPostLoginURL, "https://") {
		errs = append(errs, "USER_OAUTH_FRONTEND_POST_LOGIN_URL must start with https:// in non-dev environments")
	}

	if strings.TrimSpace(c.OAuthStateHMACSecret) == "" {
		errs = append(errs, "USER_OAUTH_STATE_HMAC_SECRET is required when any OAuth provider is configured")
	} else if len(c.OAuthStateHMACSecret) < minOAuthHMACSecretLen {
		errs = append(errs, "USER_OAUTH_STATE_HMAC_SECRET must be at least 32 characters")
	}

	return errs
}

// validateUserRateLimit checks the per-authenticated-user rate limiter settings.
// perMin == 0 disables the limiter (valid for gateway-layer rate-limiting environments).
// When perMin > 0 the burst MUST also be positive — a zero-burst token bucket admits no
// requests at all and is almost certainly a misconfiguration.
func (c *Config) validateUserRateLimit() []string {
	var errs []string

	if c.UserRateLimitPerMin < 0 {
		errs = append(errs, "USER_USER_RATE_LIMIT_PER_MIN must be >= 0 (0 disables the limiter)")
	}

	if c.UserRateLimitPerMin > 0 && c.UserRateLimitBurst <= 0 {
		errs = append(errs, "USER_USER_RATE_LIMIT_BURST must be > 0 when USER_USER_RATE_LIMIT_PER_MIN > 0")
	}

	return errs
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

	errs = append(errs, c.validateEventHMAC()...)
	errs = append(errs, c.validatePIIAndSMTP()...)
	errs = append(errs, c.validateMFA()...)
	errs = append(errs, c.validateGatewayHMAC()...)

	return errs
}

// validateEventHMAC checks the EVENT_HMAC_SECRET field.
//
// P0: outside development, the event HMAC secret MUST be present, ≥32 chars, and
// not a known development-default value. Without a valid secret, inbound
// kyc.tier_changed events cannot be authenticated and a forged Redis publish
// could elevate any user to Tier2. In development we allow an empty secret
// (the consumer then drops all signed events — fail-closed).
func (c *Config) validateEventHMAC() []string {
	if c.IsDev() {
		return nil
	}

	var errs []string

	switch {
	case c.EventHMACSecret == "":
		errs = append(errs, "EVENT_HMAC_SECRET is required outside development")
	case len(c.EventHMACSecret) < minEventHMACSecretLen:
		errs = append(errs, "EVENT_HMAC_SECRET must be at least 32 characters")
	case c.EventHMACSecret == devEventHMACSecret:
		errs = append(errs, "EVENT_HMAC_SECRET must not be a known development-default value")
	}

	return errs
}

// minGatewayHMACSecretLen is the minimum length of the gateway HMAC secret. It mirrors
// the gateway's GATEWAY_HMAC_SECRET ≥32-char requirement (conventions §24.1).
const minGatewayHMACSecretLen = 32

// minCommsS2STokenLen is the minimum length of the USER_COMMS_S2S_TOKEN bearer secret.
// 32 chars matches the SHA-256 block size and resists brute force — mirrors minEventHMACSecretLen.
const minCommsS2STokenLen = 32

// validateGatewayHMAC enforces the §24.1 fail-closed secret posture:
//   - non-dev (production/staging): secret is REQUIRED and MUST be ≥32 chars —
//     boot fails fast otherwise (mirrors the gateway which fails fast in non-dev).
//   - dev: secret may be empty (verification disabled, mirroring the gateway's
//     dev signing-skip); but if a secret IS provided it must still be ≥32 chars
//     so a too-short dev secret never masquerades as a valid one.
func (c *Config) validateGatewayHMAC() []string {
	var errs []string

	if !c.IsDev() {
		if len(c.GatewayHMACSecret) < minGatewayHMACSecretLen {
			errs = append(errs, "USER_GATEWAY_HMAC_SECRET must be at least 32 characters in non-dev environments")
		}

		return errs
	}

	// Dev: empty is allowed (verification disabled); non-empty must be ≥32.
	if c.GatewayHMACSecret != "" && len(c.GatewayHMACSecret) < minGatewayHMACSecretLen {
		errs = append(errs, "USER_GATEWAY_HMAC_SECRET, when set, must be at least 32 characters")
	}

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

// validatePIIAndSMTP fail-fasts on the PII encryption key and email delivery settings.
//
// PII key (mirrors kyc config.go:151): the legal_name / national_id columns are
// always encrypted — there is NO plaintext fallback, even in dev — so a usable
// key is required in EVERY environment. Outside dev it must additionally decode to
// exactly 32 bytes. In dev a documented dev-default key (see .env.example) keeps
// the encrypt path exercised locally.
//
// Mailer: validates USER_MAILER_BACKEND + the chosen backend's required fields.
func (c *Config) validatePIIAndSMTP() []string {
	errs := c.validatePIIKey()
	errs = append(errs, c.validateMailer()...)

	return errs
}

// validatePIIKey checks the AES-256 PII encryption key.
func (c *Config) validatePIIKey() []string {
	if c.PIIEncryptionKey == "" {
		return []string{
			"USER_PII_ENCRYPTION_KEY is required when USER_ENV != development " +
				"(and a documented dev-default key is required in development): " +
				"legal_name/national_id are encrypted with no plaintext fallback " +
				"(generate with: openssl rand -base64 32)",
		}
	}

	if !c.IsDev() {
		// Non-dev: the key MUST decode to exactly 32 bytes (AES-256). In dev we skip
		// the strict length check so a short documented dev key still boots.
		key, decErr := base64.StdEncoding.DecodeString(c.PIIEncryptionKey)
		if decErr != nil || len(key) != piiKeyBytes {
			return []string{fmt.Sprintf("USER_PII_ENCRYPTION_KEY must be base64 that decodes to exactly %d bytes", piiKeyBytes)}
		}

		// Reject the publicly-known dev-default value so a prod deploy that forgets
		// to set the key never silently encrypts PII with a compromised key.
		if c.PIIEncryptionKey == devPIIEncryptionKey {
			return []string{"USER_PII_ENCRYPTION_KEY must not be a known development-default value"}
		}
	}

	return nil
}

// validateMailer checks USER_MAILER_BACKEND and the chosen backend's required fields.
func (c *Config) validateMailer() []string {
	var errs []string

	backend := strings.ToLower(strings.TrimSpace(c.MailerBackend))
	validBackends := map[string]bool{"smtp": true, mailerBackendComms: true, "": true}

	if !validBackends[backend] {
		errs = append(errs, "USER_MAILER_BACKEND must be smtp|comms")
	}

	if backend == mailerBackendComms {
		errs = append(errs, c.validateCommsBackend()...)
	}

	if !c.IsDev() && backend != mailerBackendComms && c.SMTPHost == "" {
		errs = append(errs, "USER_SMTP_HOST is required when USER_ENV != development (unless USER_MAILER_BACKEND=comms)")
	}

	if !c.IsDev() && strings.TrimSpace(c.AppBaseURL) == "" {
		errs = append(errs, "USER_APP_BASE_URL is required when USER_ENV != development")
	}

	if backend != mailerBackendComms && c.SMTPHost != "" && strings.TrimSpace(c.AppBaseURL) == "" {
		errs = append(errs, "USER_APP_BASE_URL is required when USER_SMTP_HOST is set")
	}

	return errs
}

// validateCommsBackend checks USER_COMMS_BASE_URL and USER_COMMS_S2S_TOKEN when
// USER_MAILER_BACKEND=comms. In non-dev: BaseURL MUST be https (prevents X-Service-Token
// leakage over plaintext); S2S token MUST be ≥32 chars (mirrors EVENT_HMAC_SECRET posture).
func (c *Config) validateCommsBackend() []string {
	var errs []string

	if strings.TrimSpace(c.CommsBaseURL) == "" {
		errs = append(errs, "USER_COMMS_BASE_URL is required when USER_MAILER_BACKEND=comms")
	} else if !c.IsDev() && !strings.HasPrefix(c.CommsBaseURL, "https://") {
		errs = append(errs, "USER_COMMS_BASE_URL must start with https:// in non-dev environments")
	}

	if strings.TrimSpace(c.CommsS2SToken) == "" {
		errs = append(errs, "USER_COMMS_S2S_TOKEN is required when USER_MAILER_BACKEND=comms")
	} else if !c.IsDev() && len(strings.TrimSpace(c.CommsS2SToken)) < minCommsS2STokenLen {
		errs = append(errs, "USER_COMMS_S2S_TOKEN must be at least 32 characters in non-dev environments")
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
