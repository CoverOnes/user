// Package config handles environment-first configuration loading.
package config

import (
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

	// Redis
	RedisURL string `mapstructure:"redis_url"`

	// JWT
	JWTPrivateKey    string `mapstructure:"jwt_private_key"`     // base64 32-byte Ed25519 seed
	JWTPrivateKeyPEM string `mapstructure:"jwt_private_key_pem"` // PKCS8 PEM alternative

	// Access token TTL in seconds (default 600)
	AccessTokenTTLSec int `mapstructure:"access_token_ttl_sec"`

	// Refresh token TTL in hours (default 24)
	RefreshTokenTTLHours int `mapstructure:"refresh_token_ttl_hours"`

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
	bindings := map[string]string{
		"port":                    "USER_PORT",
		"postgres_dsn":            "USER_POSTGRES_DSN",
		"postgres_schema":         "USER_DB_SCHEMA",
		"redis_url":               "USER_REDIS_URL",
		"jwt_private_key":         "USER_JWT_PRIVATE_KEY",
		"jwt_private_key_pem":     "USER_JWT_PRIVATE_KEY_PEM",
		"access_token_ttl_sec":    "USER_ACCESS_TOKEN_TTL_SEC",
		"refresh_token_ttl_hours": "USER_REFRESH_TOKEN_TTL_HOURS",
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

	if c.PostgresSchema != "" && !schemaNameRe.MatchString(c.PostgresSchema) {
		errs = append(errs, "USER_DB_SCHEMA must start with a letter or underscore and contain only [a-zA-Z0-9_] characters")
	}

	if len(errs) > 0 {
		return errors.New("config validation failed: " + strings.Join(errs, "; "))
	}

	return nil
}

// IsDev reports whether the service is running in development mode.
func (c *Config) IsDev() bool {
	return c.Env == "development"
}
