package postgres_test

import (
	"context"
	"crypto/sha256"
	"testing"
	"time"

	"github.com/CoverOnes/user/internal/crypto/pii"
	"github.com/CoverOnes/user/internal/domain"
	"github.com/CoverOnes/user/internal/store"
	"github.com/CoverOnes/user/internal/store/postgres"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// seedPendingUser inserts a PENDING_VERIFICATION user (email_verified=false) with
// encrypted identity columns and returns it.
func seedPendingUser(t *testing.T, ctx context.Context, us *postgres.UserStore, enc *pii.Encryptor, email string) *domain.User {
	t.Helper()

	legalEnc, err := enc.Encrypt("Wang Xiaoming")
	require.NoError(t, err)
	nidEnc, err := enc.Encrypt("A123456789")
	require.NoError(t, err)

	now := time.Now().UTC().Truncate(time.Millisecond)
	u := &domain.User{
		ID:            uuid.New(),
		Email:         email,
		PasswordHash:  testPasswordHash,
		DisplayName:   "Pending",
		AccountType:   "PERSONAL",
		KYCTier:       0,
		Status:        domain.UserStatusPendingVerification,
		EmailVerified: false,
		LegalNameEnc:  legalEnc,
		NationalIDEnc: nidEnc,
		CreatedAt:     now,
		UpdatedAt:     now,
	}
	require.NoError(t, us.Create(ctx, u))

	return u
}

// TestUserStore_PIIAndEmailVerified_Integration verifies the new columns round-trip
// through INSERT/SELECT and SetEmailVerified flips the flag.
func TestUserStore_PIIAndEmailVerified_Integration(t *testing.T) {
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

	t.Run("encrypted PII round-trips and decrypts", func(t *testing.T) {
		u := seedPendingUser(t, ctx, us, enc, "pii@integration.test")

		got, err := us.GetByID(ctx, u.ID)
		require.NoError(t, err)
		assert.False(t, got.EmailVerified)
		assert.Equal(t, domain.UserStatusPendingVerification, got.Status)
		require.NotEmpty(t, got.LegalNameEnc)
		require.NotEmpty(t, got.NationalIDEnc)

		legal, err := enc.Decrypt(got.LegalNameEnc)
		require.NoError(t, err)
		assert.Equal(t, "Wang Xiaoming", legal)

		nid, err := enc.Decrypt(got.NationalIDEnc)
		require.NoError(t, err)
		assert.Equal(t, "A123456789", nid)
	})

	t.Run("SetEmailVerified flips the flag and promotes to Tier 1 (idempotent)", func(t *testing.T) {
		u := seedPendingUser(t, ctx, us, enc, "verify-flag@integration.test")

		require.NoError(t, us.SetEmailVerified(ctx, u.ID))

		got, err := us.GetByID(ctx, u.ID)
		require.NoError(t, err)
		assert.True(t, got.EmailVerified)
		assert.Equal(t, int16(1), got.KYCTier)

		// Idempotent: second call still succeeds.
		require.NoError(t, us.SetEmailVerified(ctx, u.ID))
	})

	t.Run("SetEmailVerified does not downgrade an existing higher tier", func(t *testing.T) {
		u := seedPendingUser(t, ctx, us, enc, "verify-tier2@integration.test")
		require.NoError(t, us.UpdateKYCTier(ctx, u.ID, 2))

		require.NoError(t, us.SetEmailVerified(ctx, u.ID))

		got, err := us.GetByID(ctx, u.ID)
		require.NoError(t, err)
		assert.True(t, got.EmailVerified)
		assert.Equal(t, int16(2), got.KYCTier)
	})

	t.Run("SetEmailVerified on missing user returns ErrNotFound", func(t *testing.T) {
		err := us.SetEmailVerified(ctx, uuid.New())
		require.ErrorIs(t, err, domain.ErrNotFound)
	})

	t.Run("PENDING_VERIFICATION status accepted by CHECK constraint", func(t *testing.T) {
		// Already exercised by seedPendingUser, but assert explicitly that the
		// 3-value status CHECK from migration 000005 admits PENDING_VERIFICATION.
		u := seedPendingUser(t, ctx, us, enc, "pending-status@integration.test")
		got, err := us.GetByID(ctx, u.ID)
		require.NoError(t, err)
		assert.Equal(t, "PENDING_VERIFICATION", got.Status)
	})
}

// TestVerificationStore_Integration tests the email_verification_tokens lifecycle.
func TestVerificationStore_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ctx := context.Background()
	dsn := startTestDB(t)
	runMigrations(t, ctx, dsn, "")

	pool, err := postgres.NewPool(ctx, dsn, "", 0, 0)
	require.NoError(t, err)

	defer pool.Close()

	vs := postgres.NewVerificationStore(pool)

	hashOf := func(raw string) []byte {
		sum := sha256.Sum256([]byte(raw))
		return sum[:]
	}

	t.Run("create and get by hash", func(t *testing.T) {
		userID := uuid.New()
		vt := &domain.EmailVerificationToken{
			ID:        uuid.New(),
			UserID:    userID,
			TokenHash: hashOf("raw-int-1"),
			ExpiresAt: time.Now().UTC().Add(time.Hour),
			CreatedAt: time.Now().UTC(),
		}
		require.NoError(t, vs.Create(ctx, vt))

		got, err := vs.GetByHash(ctx, hashOf("raw-int-1"))
		require.NoError(t, err)
		assert.Equal(t, vt.ID, got.ID)
		assert.Equal(t, userID, got.UserID)
		assert.Nil(t, got.ConsumedAt)
	})

	t.Run("get by unknown hash returns ErrInvalidVerificationToken (no oracle)", func(t *testing.T) {
		_, err := vs.GetByHash(ctx, hashOf("never-issued"))
		require.ErrorIs(t, err, domain.ErrInvalidVerificationToken)
	})

	t.Run("mark consumed is single-use (second consume fails)", func(t *testing.T) {
		vt := &domain.EmailVerificationToken{
			ID:        uuid.New(),
			UserID:    uuid.New(),
			TokenHash: hashOf("raw-int-2"),
			ExpiresAt: time.Now().UTC().Add(time.Hour),
			CreatedAt: time.Now().UTC(),
		}
		require.NoError(t, vs.Create(ctx, vt))

		now := time.Now().UTC()
		require.NoError(t, vs.MarkConsumed(ctx, vt.ID, now))

		got, err := vs.GetByHash(ctx, hashOf("raw-int-2"))
		require.NoError(t, err)
		require.NotNil(t, got.ConsumedAt)

		// Second consume must fail (atomic single-use guard).
		err = vs.MarkConsumed(ctx, vt.ID, now)
		require.ErrorIs(t, err, domain.ErrInvalidVerificationToken)
	})

	t.Run("invalidate for user consumes all outstanding tokens", func(t *testing.T) {
		userID := uuid.New()

		vt1 := &domain.EmailVerificationToken{
			ID: uuid.New(), UserID: userID, TokenHash: hashOf("raw-int-3a"),
			ExpiresAt: time.Now().UTC().Add(time.Hour), CreatedAt: time.Now().UTC(),
		}
		vt2 := &domain.EmailVerificationToken{
			ID: uuid.New(), UserID: userID, TokenHash: hashOf("raw-int-3b"),
			ExpiresAt: time.Now().UTC().Add(time.Hour), CreatedAt: time.Now().UTC(),
		}
		require.NoError(t, vs.Create(ctx, vt1))
		require.NoError(t, vs.Create(ctx, vt2))

		require.NoError(t, vs.InvalidateForUser(ctx, userID, time.Now().UTC()))

		got1, err := vs.GetByHash(ctx, hashOf("raw-int-3a"))
		require.NoError(t, err)
		assert.NotNil(t, got1.ConsumedAt)

		got2, err := vs.GetByHash(ctx, hashOf("raw-int-3b"))
		require.NoError(t, err)
		assert.NotNil(t, got2.ConsumedAt)
	})

	t.Run("duplicate token_hash rejected by unique index", func(t *testing.T) {
		vt := &domain.EmailVerificationToken{
			ID: uuid.New(), UserID: uuid.New(), TokenHash: hashOf("raw-int-dup"),
			ExpiresAt: time.Now().UTC().Add(time.Hour), CreatedAt: time.Now().UTC(),
		}
		require.NoError(t, vs.Create(ctx, vt))

		dup := *vt
		dup.ID = uuid.New()
		err := vs.Create(ctx, &dup)
		require.Error(t, err, "duplicate token_hash must violate the unique index")
	})
}

// TestTxManager_RegisterAtomic_Integration verifies the 4-arg WithTx creates
// user + company + verification token atomically (COMPANY path), and rolls all
// three back on a company-store error.
func TestTxManager_RegisterAtomic_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ctx := context.Background()
	dsn := startTestDB(t)
	runMigrations(t, ctx, dsn, "")

	pool, err := postgres.NewPool(ctx, dsn, "", 0, 0)
	require.NoError(t, err)

	defer pool.Close()

	txMgr := postgres.NewTxManager(pool)
	us := postgres.NewUserStore(pool)
	vs := postgres.NewVerificationStore(pool)

	now := time.Now().UTC().Truncate(time.Millisecond)
	userID := uuid.New()
	tokenHash := func(raw string) []byte { sum := sha256.Sum256([]byte(raw)); return sum[:] }

	t.Run("commit creates all three rows", func(t *testing.T) {
		u := &domain.User{
			ID: userID, Email: "tx-atomic@integration.test", PasswordHash: testPasswordHash,
			DisplayName: "TxAtomic", AccountType: "COMPANY", Status: domain.UserStatusPendingVerification,
			CreatedAt: now, UpdatedAt: now,
		}
		vt := &domain.EmailVerificationToken{
			ID: uuid.New(), UserID: userID, TokenHash: tokenHash("tx-raw-1"),
			ExpiresAt: now.Add(time.Hour), CreatedAt: now,
		}

		err := txMgr.WithTx(ctx, func(
			txCtx context.Context,
			users store.UserStore,
			companies store.CompanyStore,
			verifications store.EmailVerificationTokenStore,
		) error {
			if e := users.Create(txCtx, u); e != nil {
				return e
			}
			if e := companies.Create(txCtx, &domain.Company{
				ID: uuid.New(), Name: "Atomic Inc", OwnerUserID: userID,
				Status: domain.CompanyStatusActive, CreatedAt: now, UpdatedAt: now,
			}); e != nil {
				return e
			}

			return verifications.Create(txCtx, vt)
		})
		require.NoError(t, err)

		gotUser, err := us.GetByID(ctx, userID)
		require.NoError(t, err)
		assert.Equal(t, "tx-atomic@integration.test", gotUser.Email)

		gotTok, err := vs.GetByHash(ctx, tokenHash("tx-raw-1"))
		require.NoError(t, err)
		assert.Equal(t, userID, gotTok.UserID)
	})

	t.Run("rollback on callback error leaves no rows", func(t *testing.T) {
		rollbackUserID := uuid.New()
		u := &domain.User{
			ID: rollbackUserID, Email: "tx-rollback@integration.test", PasswordHash: testPasswordHash,
			DisplayName: "TxRollback", AccountType: "PERSONAL", Status: domain.UserStatusPendingVerification,
			CreatedAt: now, UpdatedAt: now,
		}

		sentinel := assertErr("boom")
		err := txMgr.WithTx(ctx, func(
			txCtx context.Context,
			users store.UserStore,
			_ store.CompanyStore,
			verifications store.EmailVerificationTokenStore,
		) error {
			if e := users.Create(txCtx, u); e != nil {
				return e
			}
			if e := verifications.Create(txCtx, &domain.EmailVerificationToken{
				ID: uuid.New(), UserID: rollbackUserID, TokenHash: tokenHash("tx-raw-2"),
				ExpiresAt: now.Add(time.Hour), CreatedAt: now,
			}); e != nil {
				return e
			}

			return sentinel // force rollback
		})
		require.ErrorIs(t, err, sentinel)

		_, err = us.GetByID(ctx, rollbackUserID)
		require.ErrorIs(t, err, domain.ErrNotFound, "user must be rolled back")

		_, err = vs.GetByHash(ctx, tokenHash("tx-raw-2"))
		require.ErrorIs(t, err, domain.ErrInvalidVerificationToken, "token must be rolled back")
	})
}

// assertErr is a tiny error type so the rollback test can ErrorIs-match a sentinel.
type assertErr string

func (e assertErr) Error() string { return string(e) }
