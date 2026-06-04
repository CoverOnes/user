package service_test

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/CoverOnes/user/internal/crypto/pii"
	"github.com/CoverOnes/user/internal/domain"
	"github.com/CoverOnes/user/internal/service"
	"github.com/google/uuid"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mfaTestKey is a 32-byte AES-256 key used to build a REAL pii.Encryptor so the
// tests verify the TOTP secret is genuinely stored as ciphertext (not plaintext).
var mfaTestKey = []byte("0123456789abcdef0123456789abcdef")

// newMFAFixture builds an MFAService over a fake user store seeded with one ACTIVE
// user, plus a real encryptor. It returns the service, the store, and the user ID.
func newMFAFixture(t *testing.T) (*service.MFAService, *fakeUserStore, uuid.UUID) {
	t.Helper()

	enc, err := pii.NewEncryptor(mfaTestKey)
	require.NoError(t, err)

	users := newFakeUserStore()
	id := uuid.New()
	now := time.Now().UTC()
	users.put(&domain.User{
		ID:          id,
		Email:       "totp@coverones.test",
		AccountType: domain.AccountTypePersonal,
		Status:      domain.UserStatusActive,
		CreatedAt:   now,
		UpdatedAt:   now,
	})

	svc := service.NewMFAService(users, enc, "CoverOnes")

	return svc, users, id
}

// generateValidCode derives a current TOTP code from a base32 secret with the same
// parameters the service uses (30s period, 6 digits, SHA1).
func generateValidCode(t *testing.T, secret string, at time.Time) string {
	t.Helper()

	code, err := totp.GenerateCodeCustom(secret, at, totp.ValidateOpts{
		Period:    30,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	require.NoError(t, err)

	return code
}

func TestMFAService_Enroll(t *testing.T) {
	t.Run("returns valid otpauth URI and stores secret as ciphertext", func(t *testing.T) {
		svc, users, id := newMFAFixture(t)

		out, err := svc.Enroll(context.Background(), id)
		require.NoError(t, err)
		require.NotNil(t, out)

		// The provisioning URI is a parseable otpauth:// key with the right issuer +
		// account, and its embedded secret matches the returned base32 secret.
		assert.True(t, strings.HasPrefix(out.OtpauthURI, "otpauth://totp/"), "uri prefix")
		key, err := otp.NewKeyFromURL(out.OtpauthURI)
		require.NoError(t, err)
		assert.Equal(t, "CoverOnes", key.Issuer())
		assert.Equal(t, "totp@coverones.test", key.AccountName())
		assert.Equal(t, out.Secret, key.Secret())
		assert.NotEmpty(t, out.Secret)

		// MFA is NOT enabled yet (pending only).
		u, err := users.GetByID(context.Background(), id)
		require.NoError(t, err)
		assert.False(t, u.MFAEnabled, "enroll must not enable MFA")

		// The stored secret column is CIPHERTEXT — it must not contain the plaintext
		// base32 secret, and must round-trip back to it through the encryptor.
		require.NotEmpty(t, u.TOTPSecretEnc)
		assert.False(t, bytes.Contains(u.TOTPSecretEnc, []byte(out.Secret)),
			"stored secret must not contain the plaintext base32 secret")
		enc, err := pii.NewEncryptor(mfaTestKey)
		require.NoError(t, err)
		dec, err := enc.Decrypt(u.TOTPSecretEnc)
		require.NoError(t, err)
		assert.Equal(t, out.Secret, dec, "ciphertext must decrypt back to the secret")
	})

	t.Run("rejects enroll when MFA already enabled", func(t *testing.T) {
		svc, users, id := newMFAFixture(t)
		u, _ := users.GetByID(context.Background(), id)
		u.MFAEnabled = true

		_, err := svc.Enroll(context.Background(), id)
		assert.ErrorIs(t, err, domain.ErrMFAAlreadyEnabled)
	})

	t.Run("propagates not-found for unknown user", func(t *testing.T) {
		svc, _, _ := newMFAFixture(t)

		_, err := svc.Enroll(context.Background(), uuid.New())
		assert.ErrorIs(t, err, domain.ErrNotFound)
	})

	t.Run("propagates store error on persist", func(t *testing.T) {
		svc, users, id := newMFAFixture(t)
		users.setPendingSecretErr = errInjected

		_, err := svc.Enroll(context.Background(), id)
		assert.ErrorIs(t, err, errInjected)
	})
}

func TestMFAService_Confirm(t *testing.T) {
	t.Run("correct code enables MFA and returns backup codes", func(t *testing.T) {
		svc, users, id := newMFAFixture(t)

		out, err := svc.Enroll(context.Background(), id)
		require.NoError(t, err)

		code := generateValidCode(t, out.Secret, time.Now())
		conf, err := svc.Confirm(context.Background(), id, code)
		require.NoError(t, err)
		require.NotNil(t, conf)

		// Backup codes are returned exactly once, non-empty, and distinct.
		assert.Len(t, conf.BackupCodes, 10)
		seen := make(map[string]bool)
		for _, c := range conf.BackupCodes {
			assert.NotEmpty(t, c)
			assert.False(t, seen[c], "backup codes must be unique")
			seen[c] = true
		}

		u, err := users.GetByID(context.Background(), id)
		require.NoError(t, err)
		assert.True(t, u.MFAEnabled, "confirm must enable MFA")
		require.NotNil(t, u.MFAEnrolledAt)

		// The stored backup-code column is ciphertext, and contains HASHES, not the
		// raw codes — no raw code may appear in the stored bytes.
		require.NotEmpty(t, u.MFABackupCodesEnc)
		for _, c := range conf.BackupCodes {
			assert.False(t, bytes.Contains(u.MFABackupCodesEnc, []byte(c)),
				"stored backup codes must not contain a raw code")
		}
		enc, err := pii.NewEncryptor(mfaTestKey)
		require.NoError(t, err)
		dec, err := enc.Decrypt(u.MFABackupCodesEnc)
		require.NoError(t, err)
		var hashes []string
		require.NoError(t, json.Unmarshal([]byte(dec), &hashes))
		assert.Len(t, hashes, 10)
	})

	t.Run("code within prior-step skew window is accepted", func(t *testing.T) {
		svc, _, id := newMFAFixture(t)

		out, err := svc.Enroll(context.Background(), id)
		require.NoError(t, err)

		// A code generated for 30s ago must still validate under the ±1-step skew.
		code := generateValidCode(t, out.Secret, time.Now().Add(-30*time.Second))
		_, err = svc.Confirm(context.Background(), id, code)
		require.NoError(t, err)
	})

	t.Run("wrong code is rejected without enabling MFA", func(t *testing.T) {
		svc, users, id := newMFAFixture(t)

		_, err := svc.Enroll(context.Background(), id)
		require.NoError(t, err)

		_, err = svc.Confirm(context.Background(), id, "000000")
		assert.ErrorIs(t, err, domain.ErrInvalidTOTPCode)

		u, _ := users.GetByID(context.Background(), id)
		assert.False(t, u.MFAEnabled, "a bad code must not enable MFA")
	})

	t.Run("confirm without prior enroll returns not-enrolled", func(t *testing.T) {
		svc, _, id := newMFAFixture(t)

		_, err := svc.Confirm(context.Background(), id, "123456")
		assert.ErrorIs(t, err, domain.ErrMFANotEnrolled)
	})

	t.Run("confirm when already enabled is rejected", func(t *testing.T) {
		svc, users, id := newMFAFixture(t)
		out, err := svc.Enroll(context.Background(), id)
		require.NoError(t, err)
		code := generateValidCode(t, out.Secret, time.Now())
		_, err = svc.Confirm(context.Background(), id, code)
		require.NoError(t, err)

		// A second confirm on the now-enabled account must be rejected.
		_, err = svc.Confirm(context.Background(), id, code)
		assert.ErrorIs(t, err, domain.ErrMFAAlreadyEnabled)

		// store still reflects enabled state
		u, _ := users.GetByID(context.Background(), id)
		assert.True(t, u.MFAEnabled)
	})
}

func TestMFAService_Verify(t *testing.T) {
	// helper: enroll + confirm so the user is MFA-enabled, returning the secret.
	enabled := func(t *testing.T) (*service.MFAService, uuid.UUID, string) {
		t.Helper()
		svc, _, id := newMFAFixture(t)
		out, err := svc.Enroll(context.Background(), id)
		require.NoError(t, err)
		code := generateValidCode(t, out.Secret, time.Now())
		_, err = svc.Confirm(context.Background(), id, code)
		require.NoError(t, err)

		return svc, id, out.Secret
	}

	t.Run("valid code for enabled user succeeds", func(t *testing.T) {
		svc, id, secret := enabled(t)

		code := generateValidCode(t, secret, time.Now())
		require.NoError(t, svc.Verify(context.Background(), id, code))
	})

	t.Run("invalid code for enabled user returns invalid", func(t *testing.T) {
		svc, id, _ := enabled(t)

		err := svc.Verify(context.Background(), id, "000000")
		assert.ErrorIs(t, err, domain.ErrInvalidTOTPCode)
	})

	t.Run("verify for non-enabled user returns not-enrolled", func(t *testing.T) {
		svc, _, id := newMFAFixture(t)

		err := svc.Verify(context.Background(), id, "123456")
		assert.ErrorIs(t, err, domain.ErrMFANotEnrolled)
	})

	t.Run("malformed (wrong length) code is invalid, not an error", func(t *testing.T) {
		svc, id, _ := enabled(t)

		err := svc.Verify(context.Background(), id, "12")
		assert.ErrorIs(t, err, domain.ErrInvalidTOTPCode)
	})
}

func TestMFAService_Disable(t *testing.T) {
	enabled := func(t *testing.T) (*service.MFAService, *fakeUserStore, uuid.UUID, string, []string) {
		t.Helper()
		svc, users, id := newMFAFixture(t)
		out, err := svc.Enroll(context.Background(), id)
		require.NoError(t, err)
		code := generateValidCode(t, out.Secret, time.Now())
		conf, err := svc.Confirm(context.Background(), id, code)
		require.NoError(t, err)

		return svc, users, id, out.Secret, conf.BackupCodes
	}

	t.Run("valid TOTP code disables and clears all MFA state", func(t *testing.T) {
		svc, users, id, secret, _ := enabled(t)

		code := generateValidCode(t, secret, time.Now())
		require.NoError(t, svc.Disable(context.Background(), id, code))

		u, _ := users.GetByID(context.Background(), id)
		assert.False(t, u.MFAEnabled)
		assert.Empty(t, u.TOTPSecretEnc)
		assert.Empty(t, u.MFABackupCodesEnc)
		assert.Nil(t, u.MFAEnrolledAt)
	})

	t.Run("valid backup code also disables", func(t *testing.T) {
		svc, users, id, _, backupCodes := enabled(t)

		require.NoError(t, svc.Disable(context.Background(), id, backupCodes[0]))

		u, _ := users.GetByID(context.Background(), id)
		assert.False(t, u.MFAEnabled)
	})

	t.Run("wrong code does not disable", func(t *testing.T) {
		svc, users, id, _, _ := enabled(t)

		err := svc.Disable(context.Background(), id, "000000")
		assert.ErrorIs(t, err, domain.ErrInvalidTOTPCode)

		u, _ := users.GetByID(context.Background(), id)
		assert.True(t, u.MFAEnabled, "a bad code must leave MFA enabled")
	})

	t.Run("disable on a non-enabled user returns not-enrolled", func(t *testing.T) {
		svc, _, id := newMFAFixture(t)

		err := svc.Disable(context.Background(), id, "123456")
		assert.ErrorIs(t, err, domain.ErrMFANotEnrolled)
	})
}
