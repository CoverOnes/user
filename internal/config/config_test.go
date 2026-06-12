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
		"USER_ENV", envDevelopment,
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
		"USER_ENV", envDevelopment,
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

func TestLoad_AppBaseURL_DevCanBeEmptyWhenSMTPUnset(t *testing.T) {
	setEnv(
		t,
		"USER_POSTGRES_DSN", "postgres://user:pass@localhost/testdb",
		"USER_PORT", "8080",
		"USER_LOG_LEVEL", "INFO",
		"USER_SMTP_HOST", "",
	)

	os.Unsetenv("USER_APP_BASE_URL") //nolint:errcheck // test cleanup

	cfg, err := config.Load()
	require.NoError(t, err)
	assert.Empty(t, cfg.AppBaseURL, "USER_APP_BASE_URL must not be invented by code")
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
		"USER_ENV", envDevelopment,
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

// envProduction and envDevelopment are the canonical env string values used across
// config tests. Declared as constants to satisfy the goconst linter and avoid drift.
const (
	envProduction  = "production"
	envDevelopment = "development"
)

// setProdSecrets sets the PII key + SMTP host that every production-env load now
// requires, so a test can isolate the specific field it asserts on.
func setProdSecrets(t *testing.T) {
	t.Helper()

	t.Setenv("USER_PII_ENCRYPTION_KEY", validPIIKeyB64)
	t.Setenv("USER_SMTP_HOST", "smtp.example.com")
	t.Setenv("USER_APP_BASE_URL", "https://app.coverones.com")
}

func TestLoad_EventHMACSecret_ProdRequired(t *testing.T) {
	setEnv(
		t,
		"USER_POSTGRES_DSN", "postgres://user:pass@localhost/testdb",
		"USER_PORT", "8080",
		"USER_LOG_LEVEL", "INFO",
		"USER_ENV", envProduction,
		"USER_JWT_PRIVATE_KEY", "dGVzdC1zZWVkLTMyLWJ5dGVzLXh4eHh4eHh4eHg=",
		"EVENT_HMAC_SECRET", "",
		"USER_GATEWAY_HMAC_SECRET", testGatewayHMACSecret,
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
		"USER_ENV", envProduction,
		"USER_JWT_PRIVATE_KEY", "dGVzdC1zZWVkLTMyLWJ5dGVzLXh4eHh4eHh4eHg=",
		"EVENT_HMAC_SECRET", "too-short",
		"USER_GATEWAY_HMAC_SECRET", testGatewayHMACSecret,
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
		"USER_ENV", envProduction,
		"USER_JWT_PRIVATE_KEY", "dGVzdC1zZWVkLTMyLWJ5dGVzLXh4eHh4eHh4eHg=",
		"EVENT_HMAC_SECRET", "this-is-a-32-byte-test-secret-xx",
		"USER_GATEWAY_HMAC_SECRET", testGatewayHMACSecret,
	)
	setProdSecrets(t)

	cfg, err := config.Load()
	require.NoError(t, err)
	assert.Equal(t, "this-is-a-32-byte-test-secret-xx", cfg.EventHMACSecret)
}

// testGatewayHMACSecret is a 32-char placeholder gateway HMAC secret used in tests — not real.
const testGatewayHMACSecret = "0123456789abcdef0123456789abcdef"

// setBaseProdEnv sets the common production-env base (DSN/port/log/env/JWT/HMAC)
// WITHOUT the PII key or SMTP host, so each test can flip exactly those.
// Includes USER_GATEWAY_HMAC_SECRET (§24.1 fail-closed: required in production).
func setBaseProdEnv(t *testing.T) {
	t.Helper()

	setEnv(
		t,
		"USER_POSTGRES_DSN", "postgres://user:pass@localhost/testdb",
		"USER_PORT", "8080",
		"USER_LOG_LEVEL", "INFO",
		"USER_ENV", envProduction,
		"USER_JWT_PRIVATE_KEY", "dGVzdC1zZWVkLTMyLWJ5dGVzLXh4eHh4eHh4eHg=",
		"EVENT_HMAC_SECRET", "this-is-a-32-byte-test-secret-xx",
		"USER_GATEWAY_HMAC_SECRET", testGatewayHMACSecret,
	)
}

func TestLoad_PIIKey_DevRequiresKey(t *testing.T) {
	// In dev a key is still required (no plaintext fallback) — but a short dev
	// default is allowed (no strict 32-byte check).
	setEnv(
		t,
		"USER_POSTGRES_DSN", "postgres://user:pass@localhost/testdb",
		"USER_ENV", envDevelopment,
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
		"USER_ENV", envDevelopment,
		"USER_PII_ENCRYPTION_KEY", "dev-default-not-32-bytes",
	)

	cfg, err := config.Load()
	require.NoError(t, err)
	assert.Equal(t, "dev-default-not-32-bytes", cfg.PIIEncryptionKey)
}

func TestLoad_PIIKey_ProdMissingFails(t *testing.T) {
	setBaseProdEnv(t)
	t.Setenv("USER_SMTP_HOST", "smtp.example.com")
	t.Setenv("USER_APP_BASE_URL", "https://app.coverones.com")
	t.Setenv("USER_PII_ENCRYPTION_KEY", "")

	_, err := config.Load()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "USER_PII_ENCRYPTION_KEY")
}

func TestLoad_PIIKey_ProdWrongLengthFails(t *testing.T) {
	setBaseProdEnv(t)
	t.Setenv("USER_SMTP_HOST", "smtp.example.com")
	t.Setenv("USER_APP_BASE_URL", "https://app.coverones.com")
	// Valid base64 but decodes to 16 bytes, not 32.
	t.Setenv("USER_PII_ENCRYPTION_KEY", "MDEyMzQ1Njc4OWFiY2RlZg==")

	_, err := config.Load()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "USER_PII_ENCRYPTION_KEY")
}

func TestLoad_PIIKey_ProdNotBase64Fails(t *testing.T) {
	setBaseProdEnv(t)
	t.Setenv("USER_SMTP_HOST", "smtp.example.com")
	t.Setenv("USER_APP_BASE_URL", "https://app.coverones.com")
	t.Setenv("USER_PII_ENCRYPTION_KEY", "not!valid!base64!!!")

	_, err := config.Load()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "USER_PII_ENCRYPTION_KEY")
}

func TestLoad_SMTPHost_ProdRequired(t *testing.T) {
	setBaseProdEnv(t)
	t.Setenv("USER_PII_ENCRYPTION_KEY", validPIIKeyB64)
	t.Setenv("USER_SMTP_HOST", "")
	t.Setenv("USER_APP_BASE_URL", "https://app.coverones.com")

	_, err := config.Load()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "USER_SMTP_HOST")
}

func TestLoad_AppBaseURL_ProdRequired(t *testing.T) {
	setBaseProdEnv(t)
	t.Setenv("USER_PII_ENCRYPTION_KEY", validPIIKeyB64)
	t.Setenv("USER_SMTP_HOST", "smtp.example.com")
	t.Setenv("USER_APP_BASE_URL", "")

	_, err := config.Load()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "USER_APP_BASE_URL")
}

func TestLoad_AppBaseURL_RequiredWhenSMTPConfigured(t *testing.T) {
	setEnv(
		t,
		"USER_POSTGRES_DSN", "postgres://user:pass@localhost/testdb",
		"USER_ENV", envDevelopment,
		"USER_SMTP_HOST", "localhost",
		"USER_APP_BASE_URL", "",
	)

	_, err := config.Load()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "USER_APP_BASE_URL")
}

func TestLoad_ProdAllSecretsValid(t *testing.T) {
	setBaseProdEnv(t)
	t.Setenv("USER_PII_ENCRYPTION_KEY", validPIIKeyB64)
	t.Setenv("USER_SMTP_HOST", "smtp.example.com")
	t.Setenv("USER_APP_BASE_URL", "https://app.coverones.com")

	cfg, err := config.Load()
	require.NoError(t, err)
	assert.Equal(t, validPIIKeyB64, cfg.PIIEncryptionKey)
	assert.Equal(t, "smtp.example.com", cfg.SMTPHost)
	assert.Equal(t, "https://app.coverones.com", cfg.AppBaseURL)
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

// TestLoad_GatewayHMAC verifies §24.1 fail-closed secret posture for USER_GATEWAY_HMAC_SECRET.
func TestLoad_GatewayHMAC(t *testing.T) {
	tests := []struct {
		name      string
		env       string
		secret    string
		wantErr   bool
		errSubstr string
	}{
		{
			// §24.1: dev may omit the secret (verification disabled).
			name:    "dev with empty secret is allowed",
			env:     envDevelopment,
			secret:  "",
			wantErr: false,
		},
		{
			// §24.1: non-dev MUST have a ≥32-char secret — boot fails fast.
			name:      "production without gateway secret fails (fail-closed)",
			env:       envProduction,
			secret:    "",
			wantErr:   true,
			errSubstr: "USER_GATEWAY_HMAC_SECRET must be at least 32 characters in non-dev",
		},
		{
			// Even in dev a too-short secret is an error (catches typos).
			name:      "dev with too-short secret is rejected",
			env:       envDevelopment,
			secret:    "tooshort",
			wantErr:   true,
			errSubstr: "USER_GATEWAY_HMAC_SECRET, when set, must be at least 32 characters",
		},
		{
			name:      "production with too-short secret is rejected",
			env:       envProduction,
			secret:    "tooshort",
			wantErr:   true,
			errSubstr: "USER_GATEWAY_HMAC_SECRET must be at least 32 characters in non-dev",
		},
		{
			name:    "production with valid 32-char secret passes",
			env:     envProduction,
			secret:  testGatewayHMACSecret,
			wantErr: false,
		},
		{
			name:    "dev with valid 32-char secret passes",
			env:     envDevelopment,
			secret:  testGatewayHMACSecret,
			wantErr: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Non-dev tests need all production secrets set (PII key + SMTP + event HMAC);
			// the gateway HMAC field under test is set explicitly after.
			if tc.env == envProduction {
				setEnv(
					t,
					"USER_POSTGRES_DSN", "postgres://user:pass@localhost/testdb",
					"USER_PORT", "8080",
					"USER_LOG_LEVEL", "INFO",
					"USER_ENV", tc.env,
					"USER_JWT_PRIVATE_KEY", "dGVzdC1zZWVkLTMyLWJ5dGVzLXh4eHh4eHh4eHg=",
					"EVENT_HMAC_SECRET", "this-is-a-32-byte-test-secret-xx",
				)
				setProdSecrets(t)
			} else {
				setEnv(
					t,
					"USER_POSTGRES_DSN", "postgres://user:pass@localhost/testdb",
					"USER_PORT", "8080",
					"USER_LOG_LEVEL", "INFO",
					"USER_ENV", tc.env,
				)
			}

			t.Setenv("USER_GATEWAY_HMAC_SECRET", tc.secret)

			_, err := config.Load()
			if tc.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.errSubstr)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// testCommsS2SToken is a valid 32-char test token — not a real credential.
const testCommsS2SToken = "0123456789abcdef0123456789abcdef"

// setBaseCommsEnv configures the minimal production environment with
// USER_MAILER_BACKEND=comms, so individual tests can vary comms-specific fields.
func setBaseCommsEnv(t *testing.T) {
	t.Helper()

	setBaseProdEnv(t)
	// Comms backend: SMTP host not required when backend=comms.
	t.Setenv("USER_SMTP_HOST", "")
	t.Setenv("USER_PII_ENCRYPTION_KEY", validPIIKeyB64)
	t.Setenv("USER_APP_BASE_URL", "https://app.coverones.com")
	t.Setenv("USER_MAILER_BACKEND", "comms")
}

// TestLoad_ValidateUserRateLimit covers all branches of validateUserRateLimit:
// negative perMin is rejected, zero-burst with positive perMin is rejected,
// zero perMin (disabled) is accepted, and a fully-valid pair is accepted.
func TestLoad_ValidateUserRateLimit(t *testing.T) {
	tests := []struct {
		name      string
		perMin    string
		burst     string
		wantErr   bool
		errSubstr string
	}{
		{
			name:      "perMin < 0 is rejected",
			perMin:    "-1",
			burst:     "10",
			wantErr:   true,
			errSubstr: "USER_USER_RATE_LIMIT_PER_MIN must be >= 0",
		},
		{
			name:      "perMin > 0 with burst <= 0 is rejected",
			perMin:    "60",
			burst:     "0",
			wantErr:   true,
			errSubstr: "USER_USER_RATE_LIMIT_BURST must be > 0",
		},
		{
			name:    "perMin = 0 disables limiter (no-op pass)",
			perMin:  "0",
			burst:   "0",
			wantErr: false,
		},
		{
			name:    "valid perMin > 0 and burst > 0 passes",
			perMin:  "120",
			burst:   "20",
			wantErr: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Cannot use t.Parallel() here: setEnv calls t.Setenv, which is
			// incompatible with parallel subtests (panic in Go 1.21+).
			setEnv(
				t,
				"USER_POSTGRES_DSN", "postgres://user:pass@localhost/testdb",
				"USER_PORT", "8080",
				"USER_LOG_LEVEL", "INFO",
				"USER_ENV", envDevelopment,
				"USER_USER_RATE_LIMIT_PER_MIN", tc.perMin,
				"USER_USER_RATE_LIMIT_BURST", tc.burst,
			)

			_, err := config.Load()
			if tc.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.errSubstr)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// TestLoad_CommsMailer validates USER_COMMS_S2S_TOKEN and USER_COMMS_BASE_URL
// enforcement in dev vs non-dev — mirrors the EVENT_HMAC_SECRET / GATEWAY_HMAC_SECRET pattern.
func TestLoad_CommsMailer(t *testing.T) {
	tests := []struct {
		name      string
		env       string
		baseURL   string
		s2sToken  string
		wantErr   bool
		errSubstr string
	}{
		{
			name:      "non-dev short S2S token rejected",
			env:       envProduction,
			baseURL:   "https://notification.internal:8084",
			s2sToken:  "too-short",
			wantErr:   true,
			errSubstr: "USER_COMMS_S2S_TOKEN must be at least 32 characters in non-dev",
		},
		{
			name:      "non-dev http BaseURL rejected",
			env:       envProduction,
			baseURL:   "http://notification.internal:8084",
			s2sToken:  testCommsS2SToken,
			wantErr:   true,
			errSubstr: "USER_COMMS_BASE_URL must start with https:// in non-dev",
		},
		{
			name:     "non-dev valid 32-char token + https BaseURL passes",
			env:      envProduction,
			baseURL:  "https://notification.internal:8084",
			s2sToken: testCommsS2SToken,
			wantErr:  false,
		},
		{
			name:     "dev short token allowed",
			env:      envDevelopment,
			baseURL:  "http://notification:8084",
			s2sToken: "short",
			wantErr:  false,
		},
		{
			name:     "dev http BaseURL allowed",
			env:      envDevelopment,
			baseURL:  "http://notification:8084",
			s2sToken: testCommsS2SToken,
			wantErr:  false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.env == envProduction {
				setBaseCommsEnv(t)
				t.Setenv("USER_ENV", envProduction)
			} else {
				setEnv(
					t,
					"USER_POSTGRES_DSN", "postgres://user:pass@localhost/testdb",
					"USER_PORT", "8080",
					"USER_LOG_LEVEL", "INFO",
					"USER_ENV", envDevelopment,
					"USER_MAILER_BACKEND", "comms",
				)
			}

			t.Setenv("USER_COMMS_BASE_URL", tc.baseURL)
			t.Setenv("USER_COMMS_S2S_TOKEN", tc.s2sToken)

			_, err := config.Load()
			if tc.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.errSubstr)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// TestLoad_DevConstantDenylist verifies that the denylist for well-known
// development-default secret values is enforced in non-dev but allowed in dev.
// Table: {field, env-var, dev-constant value} × {dev, production}.
func TestLoad_DevConstantDenylist(t *testing.T) {
	const devEventHMAC = "dev-shared-event-hmac-secret-min32-0123456789"
	const devPIIKey = "Y292ZXJvbmVzLWRldi1waWkta2V5LTMyYnl0ZXNsZW4="

	tests := []struct {
		name        string
		envOverride map[string]string
		env         string
		wantErr     bool
		errContains string
	}{
		{
			name: "prod: dev-constant EVENT_HMAC_SECRET rejected",
			env:  envProduction,
			envOverride: map[string]string{
				"EVENT_HMAC_SECRET": devEventHMAC,
			},
			wantErr:     true,
			errContains: "must not be a known development-default value",
		},
		{
			name: "dev: dev-constant EVENT_HMAC_SECRET allowed",
			env:  envDevelopment,
			envOverride: map[string]string{
				"EVENT_HMAC_SECRET": devEventHMAC,
			},
			wantErr: false,
		},
		{
			name: "prod: dev-constant USER_PII_ENCRYPTION_KEY rejected",
			env:  envProduction,
			envOverride: map[string]string{
				"USER_PII_ENCRYPTION_KEY": devPIIKey,
			},
			wantErr:     true,
			errContains: "must not be a known development-default value",
		},
		{
			name: "dev: dev-constant USER_PII_ENCRYPTION_KEY allowed (short-key dev path)",
			env:  envDevelopment,
			envOverride: map[string]string{
				// dev-constant is base64-valid and is allowed in dev (non-empty passes)
				"USER_PII_ENCRYPTION_KEY": devPIIKey,
			},
			wantErr: false,
		},
		{
			name: "prod: trailing-space dev-constant EVENT_HMAC_SECRET rejected (whitespace bypass)",
			env:  envProduction,
			envOverride: map[string]string{
				// Trailing space: without TrimSpace, len(devEventHMAC+" ") ≥ 32 passes the
				// length check AND devEventHMAC+" " != devEventHMAC bypasses the denylist →
				// the padded value would be accepted as a real secret. TrimSpace must
				// normalise it before both checks so the denylist fires correctly.
				"EVENT_HMAC_SECRET": devEventHMAC + " ",
			},
			wantErr:     true,
			errContains: "must not be a known development-default value",
		},
		{
			name: "prod: trailing-space dev-constant USER_PII_ENCRYPTION_KEY rejected (whitespace bypass)",
			env:  envProduction,
			envOverride: map[string]string{
				// Trailing space: without TrimSpace, devPIIKey+" " still decodes correctly
				// (base64 decoder ignores trailing whitespace in some impls) but more
				// importantly devPIIKey+" " != devPIIKey bypasses the denylist check.
				// TrimSpace must normalise it so the denylist fires on the clean value.
				"USER_PII_ENCRYPTION_KEY": devPIIKey + " ",
			},
			wantErr:     true,
			errContains: "must not be a known development-default value",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.env == envProduction {
				// Production needs all mandatory fields set; override only the field under test.
				setEnv(
					t,
					"USER_POSTGRES_DSN", "postgres://user:pass@localhost/testdb",
					"USER_PORT", "8080",
					"USER_LOG_LEVEL", "INFO",
					"USER_ENV", envProduction,
					"USER_JWT_PRIVATE_KEY", "dGVzdC1zZWVkLTMyLWJ5dGVzLXh4eHh4eHh4eHg=",
					"EVENT_HMAC_SECRET", "this-is-a-32-byte-test-secret-xx",
					"USER_GATEWAY_HMAC_SECRET", testGatewayHMACSecret,
				)

				setProdSecrets(t) // sets validPIIKeyB64 + SMTP host + APP_BASE_URL
			} else {
				setEnv(
					t,
					"USER_POSTGRES_DSN", "postgres://user:pass@localhost/testdb",
					"USER_PORT", "8080",
					"USER_LOG_LEVEL", "INFO",
					"USER_ENV", envDevelopment,
				)
			}

			for k, v := range tc.envOverride {
				t.Setenv(k, v)
			}

			_, err := config.Load()
			if tc.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.errContains)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
