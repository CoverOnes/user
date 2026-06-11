package postgres_test

import (
	"context"
	"testing"
	"time"

	"github.com/CoverOnes/user/internal/crypto/pii"
	"github.com/CoverOnes/user/internal/domain"
	"github.com/CoverOnes/user/internal/store/postgres"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// seedActiveUser inserts a plain ACTIVE user (no MFA) and returns it.
func seedActiveUser(t *testing.T, ctx context.Context, us *postgres.UserStore, email string) *domain.User {
	t.Helper()

	now := time.Now().UTC().Truncate(time.Millisecond)
	u := &domain.User{
		ID:           uuid.New(),
		Email:        email,
		PasswordHash: testPH(),
		DisplayName:  "MFA User",
		AccountType:  "PERSONAL",
		KYCTier:      0,
		Status:       domain.UserStatusActive,
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	require.NoError(t, us.Create(ctx, u))

	return u
}

// rawTOTPSecretEnc reads the totp_secret_enc bytea straight from the row, bypassing
// the store, so the test can assert what is ACTUALLY on disk (ciphertext).
func rawTOTPSecretEnc(t *testing.T, ctx context.Context, pool *pgxpool.Pool, id uuid.UUID) []byte {
	t.Helper()

	var raw []byte
	err := pool.QueryRow(ctx, `SELECT totp_secret_enc FROM users WHERE id = $1`, id).Scan(&raw)
	require.NoError(t, err)

	return raw
}

// TestUserStore_MFA_Integration drives the full MFA column lifecycle against a real
// Postgres: pending secret → enable → re-persist backup codes → disable. It also
// asserts the secret is stored as CIPHERTEXT (not the plaintext base32 value).
func TestUserStore_MFA_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ctx := context.Background()
	dsn := startTestDB(t)
	runMigrations(t, ctx, dsn, "")

	pool, err := postgres.NewPool(ctx, dsn, "", 0, 0)
	require.NoError(t, err)

	defer pool.Close()

	us := postgres.NewUserStore(pool)

	key := make([]byte, pii.KeySize)
	for i := range key {
		key[i] = byte(i)
	}
	enc, err := pii.NewEncryptor(key)
	require.NoError(t, err)

	t.Run("fresh user has MFA disabled and null columns", func(t *testing.T) {
		u := seedActiveUser(t, ctx, us, "mfa-fresh@integration.test")

		got, err := us.GetByID(ctx, u.ID)
		require.NoError(t, err)
		assert.False(t, got.MFAEnabled)
		assert.Empty(t, got.TOTPSecretEnc)
		assert.Empty(t, got.MFABackupCodesEnc)
		assert.Nil(t, got.MFAEnrolledAt)
	})

	t.Run("set pending secret stores ciphertext without enabling MFA", func(t *testing.T) {
		u := seedActiveUser(t, ctx, us, "mfa-pending@integration.test")

		// Canonical RFC-style base32 TOTP example, NOT a real credential — it only
		// exercises the encrypt-at-rest round trip for the totp_secret_enc column.
		const plaintextSecret = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP" //nolint:gosec // G101: test fixture, canonical base32 example not a real secret
		secretEnc, err := enc.Encrypt(plaintextSecret)
		require.NoError(t, err)

		require.NoError(t, us.SetPendingTOTPSecret(ctx, u.ID, secretEnc))

		got, err := us.GetByID(ctx, u.ID)
		require.NoError(t, err)
		assert.False(t, got.MFAEnabled, "pending secret must not enable MFA")
		require.NotEmpty(t, got.TOTPSecretEnc)

		// What is on disk is ciphertext: it must NOT equal the plaintext bytes and
		// must decrypt back to the secret.
		onDisk := rawTOTPSecretEnc(t, ctx, pool, u.ID)
		assert.NotEqual(t, []byte(plaintextSecret), onDisk)
		dec, err := enc.Decrypt(onDisk)
		require.NoError(t, err)
		assert.Equal(t, plaintextSecret, dec)
	})

	t.Run("enable MFA stores backup codes and stamps enrolled_at", func(t *testing.T) {
		u := seedActiveUser(t, ctx, us, "mfa-enable@integration.test")

		secretEnc, err := enc.Encrypt("PENDINGSECRETPENDINGSECRET123456")
		require.NoError(t, err)
		require.NoError(t, us.SetPendingTOTPSecret(ctx, u.ID, secretEnc))

		codesEnc, err := enc.Encrypt(`["hashA","hashB"]`)
		require.NoError(t, err)
		enrolledAt := time.Now().UTC().Truncate(time.Millisecond)
		require.NoError(t, us.EnableMFA(ctx, u.ID, codesEnc, enrolledAt))

		got, err := us.GetByID(ctx, u.ID)
		require.NoError(t, err)
		assert.True(t, got.MFAEnabled)
		require.NotNil(t, got.MFAEnrolledAt)
		assert.WithinDuration(t, enrolledAt, *got.MFAEnrolledAt, time.Second)
		require.NotEmpty(t, got.MFABackupCodesEnc)
		dec, err := enc.Decrypt(got.MFABackupCodesEnc)
		require.NoError(t, err)
		assert.JSONEq(t, `["hashA","hashB"]`, dec)
	})

	t.Run("set backup codes overwrites only the codes column", func(t *testing.T) {
		u := seedActiveUser(t, ctx, us, "mfa-rotate@integration.test")
		secretEnc, _ := enc.Encrypt("SECRETSECRETSECRETSECRETSECRET12")
		require.NoError(t, us.SetPendingTOTPSecret(ctx, u.ID, secretEnc))
		codesEnc, _ := enc.Encrypt(`["a"]`)
		require.NoError(t, us.EnableMFA(ctx, u.ID, codesEnc, time.Now().UTC()))

		newCodesEnc, _ := enc.Encrypt(`["b","c"]`)
		require.NoError(t, us.SetMFABackupCodes(ctx, u.ID, newCodesEnc))

		got, err := us.GetByID(ctx, u.ID)
		require.NoError(t, err)
		assert.True(t, got.MFAEnabled, "rotating codes must not change enabled state")
		dec, err := enc.Decrypt(got.MFABackupCodesEnc)
		require.NoError(t, err)
		assert.JSONEq(t, `["b","c"]`, dec)
	})

	t.Run("second EnableMFA is rejected and keeps the first backup codes (TOCTOU)", func(t *testing.T) {
		// Regression for CWE-367 against REAL Postgres: the conditional
		// (WHERE mfa_enabled = false) UPDATE must let only ONE EnableMFA win. The second
		// call returns ErrMFAAlreadyEnabled and must NOT overwrite the first code set.
		u := seedActiveUser(t, ctx, us, "mfa-toctou@integration.test")
		secretEnc, err := enc.Encrypt("TOCTOUSECRETTOCTOUSECRETTOCTOU12")
		require.NoError(t, err)
		require.NoError(t, us.SetPendingTOTPSecret(ctx, u.ID, secretEnc))

		firstCodes, err := enc.Encrypt(`["first-1","first-2"]`)
		require.NoError(t, err)
		require.NoError(t, us.EnableMFA(ctx, u.ID, firstCodes, time.Now().UTC()))

		// A second EnableMFA (the race loser) must be rejected, NOT silently overwrite.
		secondCodes, err := enc.Encrypt(`["second-1","second-2"]`)
		require.NoError(t, err)
		err = us.EnableMFA(ctx, u.ID, secondCodes, time.Now().UTC())
		assert.ErrorIs(t, err, domain.ErrMFAAlreadyEnabled)

		// The persisted backup codes are still the FIRST set.
		got, err := us.GetByID(ctx, u.ID)
		require.NoError(t, err)
		assert.True(t, got.MFAEnabled)
		dec, err := enc.Decrypt(got.MFABackupCodesEnc)
		require.NoError(t, err)
		assert.JSONEq(t, `["first-1","first-2"]`, dec, "the first confirm's codes must survive")
	})

	t.Run("disable clears every MFA column", func(t *testing.T) {
		u := seedActiveUser(t, ctx, us, "mfa-disable@integration.test")
		secretEnc, _ := enc.Encrypt("DISABLEMEDISABLEMEDISABLEME12345")
		require.NoError(t, us.SetPendingTOTPSecret(ctx, u.ID, secretEnc))
		codesEnc, _ := enc.Encrypt(`["x"]`)
		require.NoError(t, us.EnableMFA(ctx, u.ID, codesEnc, time.Now().UTC()))

		require.NoError(t, us.DisableMFA(ctx, u.ID))

		got, err := us.GetByID(ctx, u.ID)
		require.NoError(t, err)
		assert.False(t, got.MFAEnabled)
		assert.Empty(t, got.TOTPSecretEnc)
		assert.Empty(t, got.MFABackupCodesEnc)
		assert.Nil(t, got.MFAEnrolledAt)
	})

	t.Run("MFA mutators on unknown user return ErrNotFound", func(t *testing.T) {
		unknown := uuid.New()
		assert.ErrorIs(t, us.SetPendingTOTPSecret(ctx, unknown, []byte("x")), domain.ErrNotFound)
		assert.ErrorIs(t, us.EnableMFA(ctx, unknown, []byte("x"), time.Now().UTC()), domain.ErrNotFound)
		assert.ErrorIs(t, us.SetMFABackupCodes(ctx, unknown, []byte("x")), domain.ErrNotFound)
		assert.ErrorIs(t, us.DisableMFA(ctx, unknown), domain.ErrNotFound)
	})
}
