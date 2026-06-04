package config_test

import (
	"os"
	"testing"

	"github.com/CoverOnes/user/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setEnv(t *testing.T, pairs ...string) {
	t.Helper()

	// A usable PII key is required in EVERY environment (no plaintext fallback).
	// Default it here so tests that don't care about the PII guard still load; tests
	// targeting the PII guard override it explicitly AFTER calling setEnv.
	t.Setenv("USER_PII_ENCRYPTION_KEY", "test-dev-default-pii-key")

	for i := 0; i < len(pairs)-1; i += 2 {
		t.Setenv(pairs[i], pairs[i+1])
	}
}

func TestLoad_HappyPath(t *testing.T) {
	setEnv(
		t,
		"USER_POSTGRES_DSN", "postgres://user:pass@localhost/testdb",
		"USER_PORT", "9090",
		"USER_LOG_LEVEL", "DEBUG",
		"USER_ENV", "development",
		"USER_ACCESS_TOKEN_TTL_SEC", "600",
		"USER_REFRESH_TOKEN_TTL_HOURS", "24",
	)

	cfg, err := config.Load()
	require.NoError(t, err)
	assert.Equal(t, 9090, cfg.Port)
	assert.Equal(t, "postgres://user:pass@localhost/testdb", cfg.PostgresDSN)
	assert.Equal(t, "DEBUG", cfg.LogLevel)
}

func TestLoad_MissingPostgresDSN(t *testing.T) {
	os.Unsetenv("USER_POSTGRES_DSN") //nolint:errcheck // test cleanup

	setEnv(
		t,
		"USER_PORT", "8080",
		"USER_LOG_LEVEL", "INFO",
		"USER_ENV", "development",
	)

	_, err := config.Load()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "USER_POSTGRES_DSN")
}

func TestLoad_InvalidPort(t *testing.T) {
	setEnv(
		t,
		"USER_POSTGRES_DSN", "postgres://user:pass@localhost/testdb",
		"USER_PORT", "99999",
	)

	_, err := config.Load()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "USER_PORT")
}

func TestLoad_InvalidLogLevel(t *testing.T) {
	setEnv(
		t,
		"USER_POSTGRES_DSN", "postgres://user:pass@localhost/testdb",
		"USER_PORT", "8080",
		"USER_LOG_LEVEL", "VERBOSE",
	)

	_, err := config.Load()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "USER_LOG_LEVEL")
}

func TestLoad_Defaults(t *testing.T) {
	setEnv(
		t,
		"USER_POSTGRES_DSN", "postgres://user:pass@localhost/testdb",
	)

	// Clear optional fields to verify defaults.
	os.Unsetenv("USER_PORT")                    //nolint:errcheck // test cleanup
	os.Unsetenv("USER_LOG_LEVEL")               //nolint:errcheck // test cleanup
	os.Unsetenv("USER_ACCESS_TOKEN_TTL_SEC")    //nolint:errcheck // test cleanup
	os.Unsetenv("USER_REFRESH_TOKEN_TTL_HOURS") //nolint:errcheck // test cleanup
	os.Unsetenv("USER_DB_SCHEMA")               //nolint:errcheck // test cleanup

	cfg, err := config.Load()
	require.NoError(t, err)
	assert.Equal(t, 8080, cfg.Port)
	assert.Equal(t, "INFO", cfg.LogLevel)
	assert.Equal(t, 600, cfg.AccessTokenTTLSec)
	assert.Equal(t, 24, cfg.RefreshTokenTTLHours)
	assert.Equal(t, "", cfg.PostgresSchema)
}

func TestLoad_AppBaseURL_DefaultsToDevOrigin(t *testing.T) {
	setEnv(
		t,
		"USER_POSTGRES_DSN", "postgres://user:pass@localhost/testdb",
		"USER_PORT", "8080",
		"USER_LOG_LEVEL", "INFO",
	)

	os.Unsetenv("USER_APP_BASE_URL") //nolint:errcheck // test cleanup

	cfg, err := config.Load()
	require.NoError(t, err)
	assert.Equal(t, "http://localhost:5500", cfg.AppBaseURL, "USER_APP_BASE_URL must default to the dev frontend origin")
}

func TestLoad_AppBaseURL_Configurable(t *testing.T) {
	setEnv(
		t,
		"USER_POSTGRES_DSN", "postgres://user:pass@localhost/testdb",
		"USER_PORT", "8080",
		"USER_LOG_LEVEL", "INFO",
		"USER_APP_BASE_URL", "https://app.coverones.com",
	)

	cfg, err := config.Load()
	require.NoError(t, err)
	assert.Equal(t, "https://app.coverones.com", cfg.AppBaseURL)
}

func TestLoad_PostgresSchema_Valid(t *testing.T) {
	setEnv(
		t,
		"USER_POSTGRES_DSN", "postgres://user:pass@localhost/testdb",
		"USER_PORT", "8080",
		"USER_LOG_LEVEL", "INFO",
		"USER_DB_SCHEMA", "user_service",
	)

	cfg, err := config.Load()
	require.NoError(t, err)
	assert.Equal(t, "user_service", cfg.PostgresSchema)
}

func TestLoad_PostgresSchema_Empty(t *testing.T) {
	setEnv(
		t,
		"USER_POSTGRES_DSN", "postgres://user:pass@localhost/testdb",
		"USER_PORT", "8080",
		"USER_LOG_LEVEL", "INFO",
		"USER_DB_SCHEMA", "",
	)

	cfg, err := config.Load()
	require.NoError(t, err)
	assert.Equal(t, "", cfg.PostgresSchema)
}

func TestLoad_PostgresSchema_Invalid(t *testing.T) {
	setEnv(
		t,
		"USER_POSTGRES_DSN", "postgres://user:pass@localhost/testdb",
		"USER_PORT", "8080",
		"USER_LOG_LEVEL", "INFO",
		"USER_DB_SCHEMA", "bad-schema!",
	)

	_, err := config.Load()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "USER_DB_SCHEMA")
}

func TestLoad_PostgresSchema_LeadingDigitRejected(t *testing.T) {
	setEnv(
		t,
		"USER_POSTGRES_DSN", "postgres://user:pass@localhost/testdb",
		"USER_PORT", "8080",
		"USER_LOG_LEVEL", "INFO",
		"USER_DB_SCHEMA", "1schema",
	)

	_, err := config.Load()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "USER_DB_SCHEMA")
}

func TestLoad_EventHMACSecret_DevOptional(t *testing.T) {
	setEnv(
		t,
		"USER_POSTGRES_DSN", "postgres://user:pass@localhost/testdb",
		"USER_PORT", "8080",
		"USER_LOG_LEVEL", "INFO",
		"USER_ENV", "development",
		// Shared, un-prefixed name; empty value exercises the dev-optional path
		// while t.Setenv guarantees restoration after the test.
		"EVENT_HMAC_SECRET", "",
	)

	cfg, err := config.Load()
	require.NoError(t, err)
	assert.Empty(t, cfg.EventHMACSecret, "dev allows an empty event HMAC secret")
}

// validPIIKeyB64 decodes to exactly 32 bytes (AES-256) — used by production-env
// config tests so they exercise the field under test, not the PII guard.
const validPIIKeyB64 = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="

// setProdSecrets sets the PII key + SMTP host that every production-env load now
// requires, so a test can isolate the specific field it asserts on.
func setProdSecrets(t *testing.T) {
	t.Helper()

	t.Setenv("USER_PII_ENCRYPTION_KEY", validPIIKeyB64)
	t.Setenv("USER_SMTP_HOST", "smtp.example.com")
}

func TestLoad_EventHMACSecret_ProdRequired(t *testing.T) {
	setEnv(
		t,
		"USER_POSTGRES_DSN", "postgres://user:pass@localhost/testdb",
		"USER_PORT", "8080",
		"USER_LOG_LEVEL", "INFO",
		"USER_ENV", "production",
		"USER_JWT_PRIVATE_KEY", "dGVzdC1zZWVkLTMyLWJ5dGVzLXh4eHh4eHh4eHg=",
		"EVENT_HMAC_SECRET", "",
	)
	setProdSecrets(t) // valid PII key + SMTP host so EVENT_HMAC is the field under test

	_, err := config.Load()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "EVENT_HMAC_SECRET")
}

func TestLoad_EventHMACSecret_ProdTooShort(t *testing.T) {
	setEnv(
		t,
		"USER_POSTGRES_DSN", "postgres://user:pass@localhost/testdb",
		"USER_PORT", "8080",
		"USER_LOG_LEVEL", "INFO",
		"USER_ENV", "production",
		"USER_JWT_PRIVATE_KEY", "dGVzdC1zZWVkLTMyLWJ5dGVzLXh4eHh4eHh4eHg=",
		"EVENT_HMAC_SECRET", "too-short",
	)
	setProdSecrets(t)

	_, err := config.Load()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "EVENT_HMAC_SECRET")
}

func TestLoad_EventHMACSecret_ProdValid(t *testing.T) {
	setEnv(
		t,
		"USER_POSTGRES_DSN", "postgres://user:pass@localhost/testdb",
		"USER_PORT", "8080",
		"USER_LOG_LEVEL", "INFO",
		"USER_ENV", "production",
		"USER_JWT_PRIVATE_KEY", "dGVzdC1zZWVkLTMyLWJ5dGVzLXh4eHh4eHh4eHg=",
		"EVENT_HMAC_SECRET", "this-is-a-32-byte-test-secret-xx",
	)
	setProdSecrets(t)

	cfg, err := config.Load()
	require.NoError(t, err)
	assert.Equal(t, "this-is-a-32-byte-test-secret-xx", cfg.EventHMACSecret)
}

// setBaseProdEnv sets the common production-env base (DSN/port/log/env/JWT/HMAC)
// WITHOUT the PII key or SMTP host, so each test can flip exactly those.
func setBaseProdEnv(t *testing.T) {
	t.Helper()

	setEnv(
		t,
		"USER_POSTGRES_DSN", "postgres://user:pass@localhost/testdb",
		"USER_PORT", "8080",
		"USER_LOG_LEVEL", "INFO",
		"USER_ENV", "production",
		"USER_JWT_PRIVATE_KEY", "dGVzdC1zZWVkLTMyLWJ5dGVzLXh4eHh4eHh4eHg=",
		"EVENT_HMAC_SECRET", "this-is-a-32-byte-test-secret-xx",
	)
}

func TestLoad_PIIKey_DevRequiresKey(t *testing.T) {
	// In dev a key is still required (no plaintext fallback) — but a short dev
	// default is allowed (no strict 32-byte check).
	setEnv(
		t,
		"USER_POSTGRES_DSN", "postgres://user:pass@localhost/testdb",
		"USER_ENV", "development",
		"USER_PII_ENCRYPTION_KEY", "",
	)

	_, err := config.Load()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "USER_PII_ENCRYPTION_KEY")
}

func TestLoad_PIIKey_DevShortKeyAccepted(t *testing.T) {
	setEnv(
		t,
		"USER_POSTGRES_DSN", "postgres://user:pass@localhost/testdb",
		"USER_ENV", "development",
		"USER_PII_ENCRYPTION_KEY", "dev-default-not-32-bytes",
	)

	cfg, err := config.Load()
	require.NoError(t, err)
	assert.Equal(t, "dev-default-not-32-bytes", cfg.PIIEncryptionKey)
}

func TestLoad_PIIKey_ProdMissingFails(t *testing.T) {
	setBaseProdEnv(t)
	t.Setenv("USER_SMTP_HOST", "smtp.example.com")
	t.Setenv("USER_PII_ENCRYPTION_KEY", "")

	_, err := config.Load()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "USER_PII_ENCRYPTION_KEY")
}

func TestLoad_PIIKey_ProdWrongLengthFails(t *testing.T) {
	setBaseProdEnv(t)
	t.Setenv("USER_SMTP_HOST", "smtp.example.com")
	// Valid base64 but decodes to 16 bytes, not 32.
	t.Setenv("USER_PII_ENCRYPTION_KEY", "MDEyMzQ1Njc4OWFiY2RlZg==")

	_, err := config.Load()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "USER_PII_ENCRYPTION_KEY")
}

func TestLoad_PIIKey_ProdNotBase64Fails(t *testing.T) {
	setBaseProdEnv(t)
	t.Setenv("USER_SMTP_HOST", "smtp.example.com")
	t.Setenv("USER_PII_ENCRYPTION_KEY", "not!valid!base64!!!")

	_, err := config.Load()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "USER_PII_ENCRYPTION_KEY")
}

func TestLoad_SMTPHost_ProdRequired(t *testing.T) {
	setBaseProdEnv(t)
	t.Setenv("USER_PII_ENCRYPTION_KEY", validPIIKeyB64)
	t.Setenv("USER_SMTP_HOST", "")

	_, err := config.Load()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "USER_SMTP_HOST")
}

func TestLoad_ProdAllSecretsValid(t *testing.T) {
	setBaseProdEnv(t)
	t.Setenv("USER_PII_ENCRYPTION_KEY", validPIIKeyB64)
	t.Setenv("USER_SMTP_HOST", "smtp.example.com")

	cfg, err := config.Load()
	require.NoError(t, err)
	assert.Equal(t, validPIIKeyB64, cfg.PIIEncryptionKey)
	assert.Equal(t, "smtp.example.com", cfg.SMTPHost)
	assert.Equal(t, 587, cfg.SMTPPort, "smtp port default must be 587")
}

func TestLoad_DBConns_Defaults(t *testing.T) {
	setEnv(
		t,
		"USER_POSTGRES_DSN", "postgres://user:pass@localhost/testdb",
		"USER_PORT", "8080",
		"USER_LOG_LEVEL", "INFO",
	)

	os.Unsetenv("USER_DB_MAX_CONNS") //nolint:errcheck // test cleanup
	os.Unsetenv("USER_DB_MIN_CONNS") //nolint:errcheck // test cleanup

	cfg, err := config.Load()
	require.NoError(t, err)
	assert.Equal(t, 10, cfg.DBMaxConns, "DBMaxConns default must be 10")
	assert.Equal(t, 2, cfg.DBMinConns, "DBMinConns default must be 2")
}

func TestLoad_DBConns_Configurable(t *testing.T) {
	setEnv(
		t,
		"USER_POSTGRES_DSN", "postgres://user:pass@localhost/testdb",
		"USER_PORT", "8080",
		"USER_LOG_LEVEL", "INFO",
		"USER_DB_MAX_CONNS", "5",
		"USER_DB_MIN_CONNS", "1",
	)

	cfg, err := config.Load()
	require.NoError(t, err)
	assert.Equal(t, 5, cfg.DBMaxConns)
	assert.Equal(t, 1, cfg.DBMinConns)
}

func TestLoad_DBConns_NegativeRejected(t *testing.T) {
	setEnv(
		t,
		"USER_POSTGRES_DSN", "postgres://user:pass@localhost/testdb",
		"USER_PORT", "8080",
		"USER_LOG_LEVEL", "INFO",
		"USER_DB_MAX_CONNS", "-1",
	)

	_, err := config.Load()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "USER_DB_MAX_CONNS")
}

func TestLoad_DBConns_OverLimitRejected(t *testing.T) {
	setEnv(
		t,
		"USER_POSTGRES_DSN", "postgres://user:pass@localhost/testdb",
		"USER_PORT", "8080",
		"USER_LOG_LEVEL", "INFO",
		"USER_DB_MIN_CONNS", "1001",
	)

	_, err := config.Load()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "USER_DB_MIN_CONNS")
}

func TestLoad_MFA_Defaults(t *testing.T) {
	setEnv(
		t,
		"USER_POSTGRES_DSN", "postgres://user:pass@localhost/testdb",
		"USER_PORT", "8080",
		"USER_LOG_LEVEL", "INFO",
	)

	os.Unsetenv("USER_TOTP_ISSUER")  //nolint:errcheck // test cleanup
	os.Unsetenv("USER_MFA_ENFORCED") //nolint:errcheck // test cleanup

	cfg, err := config.Load()
	require.NoError(t, err)
	assert.Equal(t, "CoverOnes", cfg.TOTPIssuer, "USER_TOTP_ISSUER must default to CoverOnes")
	assert.False(t, cfg.MFAEnforced, "USER_MFA_ENFORCED must default to false")
}

func TestLoad_MFA_Configurable(t *testing.T) {
	setEnv(
		t,
		"USER_POSTGRES_DSN", "postgres://user:pass@localhost/testdb",
		"USER_PORT", "8080",
		"USER_LOG_LEVEL", "INFO",
		"USER_TOTP_ISSUER", "MyApp",
		"USER_MFA_ENFORCED", "true",
	)

	cfg, err := config.Load()
	require.NoError(t, err)
	assert.Equal(t, "MyApp", cfg.TOTPIssuer)
	assert.True(t, cfg.MFAEnforced)
}

func TestLoad_TOTPIssuer_EmptyRejected(t *testing.T) {
	setEnv(
		t,
		"USER_POSTGRES_DSN", "postgres://user:pass@localhost/testdb",
		"USER_PORT", "8080",
		"USER_LOG_LEVEL", "INFO",
		"USER_TOTP_ISSUER", "   ",
	)

	_, err := config.Load()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "USER_TOTP_ISSUER")
}

func TestLoad_TOTPIssuer_ColonRejected(t *testing.T) {
	setEnv(
		t,
		"USER_POSTGRES_DSN", "postgres://user:pass@localhost/testdb",
		"USER_PORT", "8080",
		"USER_LOG_LEVEL", "INFO",
		"USER_TOTP_ISSUER", "Cover:Ones",
	)

	_, err := config.Load()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "USER_TOTP_ISSUER")
}
