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
