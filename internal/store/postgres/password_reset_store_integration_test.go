package postgres_test

import (
	"context"
	"crypto/sha256"
	"sync"
	"testing"
	"time"

	"github.com/CoverOnes/user/internal/domain"
	"github.com/CoverOnes/user/internal/store"
	"github.com/CoverOnes/user/internal/store/postgres"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// hashReset returns the SHA-256 hash of a raw reset token string.
func hashReset(raw string) []byte {
	sum := sha256.Sum256([]byte(raw))
	return sum[:]
}

// seedActiveUserForReset inserts an ACTIVE, email-verified user suitable for reset tests.
func seedActiveUserForReset(t *testing.T, ctx context.Context, us *postgres.UserStore, email string) *domain.User {
	t.Helper()

	now := time.Now().UTC().Truncate(time.Millisecond)
	u := &domain.User{
		ID:            uuid.New(),
		Email:         email,
		PasswordHash:  testPH(),
		DisplayName:   "Reset Test User",
		AccountType:   "PERSONAL",
		KYCTier:       1,
		Status:        domain.UserStatusActive,
		EmailVerified: true,
		CreatedAt:     now,
		UpdatedAt:     now,
	}
	require.NoError(t, us.Create(ctx, u))

	return u
}

// TestPasswordResetStore_Integration covers A9: Create / GetByHash / MarkUsed /
// InvalidateForUser against a real Postgres container (testcontainers-go).
func TestPasswordResetStore_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ctx := context.Background()
	dsn := startTestDB(t)
	runMigrations(t, ctx, dsn, "")

	pool, err := postgres.NewPool(ctx, dsn, "", 0, 0)
	require.NoError(t, err)

	defer pool.Close()

	rs := postgres.NewPasswordResetStore(pool)

	t.Run("create and get by hash", func(t *testing.T) {
		userID := uuid.New()
		rt := &domain.PasswordResetToken{
			ID:        uuid.New(),
			UserID:    userID,
			TokenHash: hashReset("raw-reset-1"),
			ExpiresAt: time.Now().UTC().Add(30 * time.Minute),
			CreatedAt: time.Now().UTC(),
		}
		require.NoError(t, rs.Create(ctx, rt))

		got, err := rs.GetByHash(ctx, hashReset("raw-reset-1"))
		require.NoError(t, err)
		assert.Equal(t, rt.ID, got.ID)
		assert.Equal(t, userID, got.UserID)
		assert.Nil(t, got.UsedAt)
	})

	t.Run("get by unknown hash returns ErrInvalidResetToken (no oracle)", func(t *testing.T) {
		_, err := rs.GetByHash(ctx, hashReset("never-issued-reset"))
		require.ErrorIs(t, err, domain.ErrInvalidResetToken)
	})

	t.Run("mark used is atomic single-use (second mark fails)", func(t *testing.T) {
		rt := &domain.PasswordResetToken{
			ID:        uuid.New(),
			UserID:    uuid.New(),
			TokenHash: hashReset("raw-reset-2"),
			ExpiresAt: time.Now().UTC().Add(30 * time.Minute),
			CreatedAt: time.Now().UTC(),
		}
		require.NoError(t, rs.Create(ctx, rt))

		now := time.Now().UTC()
		require.NoError(t, rs.MarkUsed(ctx, rt.ID, now))

		got, err := rs.GetByHash(ctx, hashReset("raw-reset-2"))
		require.NoError(t, err)
		require.NotNil(t, got.UsedAt)

		// Second MarkUsed must fail with ErrInvalidResetToken (CAS guard: WHERE used_at IS NULL).
		err = rs.MarkUsed(ctx, rt.ID, now)
		require.ErrorIs(t, err, domain.ErrInvalidResetToken, "second MarkUsed must fail — single-use guard")
	})

	t.Run("invalidate for user marks all outstanding tokens as used", func(t *testing.T) {
		userID := uuid.New()

		rt1 := &domain.PasswordResetToken{
			ID:        uuid.New(),
			UserID:    userID,
			TokenHash: hashReset("raw-reset-3a"),
			ExpiresAt: time.Now().UTC().Add(30 * time.Minute),
			CreatedAt: time.Now().UTC(),
		}
		rt2 := &domain.PasswordResetToken{
			ID:        uuid.New(),
			UserID:    userID,
			TokenHash: hashReset("raw-reset-3b"),
			ExpiresAt: time.Now().UTC().Add(30 * time.Minute),
			CreatedAt: time.Now().UTC(),
		}
		require.NoError(t, rs.Create(ctx, rt1))
		require.NoError(t, rs.Create(ctx, rt2))

		require.NoError(t, rs.InvalidateForUser(ctx, userID, time.Now().UTC()))

		got1, err := rs.GetByHash(ctx, hashReset("raw-reset-3a"))
		require.NoError(t, err)
		assert.NotNil(t, got1.UsedAt, "prior token 1 must be invalidated")

		got2, err := rs.GetByHash(ctx, hashReset("raw-reset-3b"))
		require.NoError(t, err)
		assert.NotNil(t, got2.UsedAt, "prior token 2 must be invalidated")
	})

	t.Run("mark used on expired token returns ErrInvalidResetToken (atomic expiry guard)", func(t *testing.T) {
		// Token whose expires_at is in the past — the SQL CAS (AND expires_at > $2)
		// must reject it atomically even if used_at IS NULL.
		rt := &domain.PasswordResetToken{
			ID:        uuid.New(),
			UserID:    uuid.New(),
			TokenHash: hashReset("raw-reset-expired-atomic"),
			ExpiresAt: time.Now().UTC().Add(-1 * time.Minute), // already expired
			CreatedAt: time.Now().UTC().Add(-31 * time.Minute),
		}
		require.NoError(t, rs.Create(ctx, rt))

		err := rs.MarkUsed(ctx, rt.ID, time.Now().UTC())
		require.ErrorIs(t, err, domain.ErrInvalidResetToken, "MarkUsed on expired token must return ErrInvalidResetToken (0 rows updated)")
	})

	t.Run("duplicate token_hash rejected by unique index", func(t *testing.T) {
		rt := &domain.PasswordResetToken{
			ID:        uuid.New(),
			UserID:    uuid.New(),
			TokenHash: hashReset("raw-reset-dup"),
			ExpiresAt: time.Now().UTC().Add(30 * time.Minute),
			CreatedAt: time.Now().UTC(),
		}
		require.NoError(t, rs.Create(ctx, rt))

		dup := *rt
		dup.ID = uuid.New()
		err := rs.Create(ctx, &dup)
		require.Error(t, err, "duplicate token_hash must violate the unique index")
	})
}

// TestPasswordResetStore_MarkUsed_TOCTOU_Integration covers A5 (concurrent double-reset):
// two goroutines race to MarkUsed on the same token. Exactly one must win via the
// Postgres-level CAS (WHERE used_at IS NULL). The loser must get ErrInvalidResetToken.
func TestPasswordResetStore_MarkUsed_TOCTOU_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ctx := context.Background()
	dsn := startTestDB(t)
	runMigrations(t, ctx, dsn, "")

	pool, err := postgres.NewPool(ctx, dsn, "", 0, 0)
	require.NoError(t, err)

	defer pool.Close()

	rs := postgres.NewPasswordResetStore(pool)

	rt := &domain.PasswordResetToken{
		ID:        uuid.New(),
		UserID:    uuid.New(),
		TokenHash: hashReset("toctou-reset-token"),
		ExpiresAt: time.Now().UTC().Add(30 * time.Minute),
		CreatedAt: time.Now().UTC(),
	}
	require.NoError(t, rs.Create(ctx, rt))

	now := time.Now().UTC()

	const goroutines = 10

	errs := make([]error, goroutines)

	var wg sync.WaitGroup
	start := make(chan struct{})

	for i := range goroutines {
		wg.Add(1)

		go func(idx int) {
			defer wg.Done()
			<-start
			errs[idx] = rs.MarkUsed(ctx, rt.ID, now)
		}(i)
	}

	close(start)
	wg.Wait()

	wins := 0

	for _, e := range errs {
		if e == nil {
			wins++
		}
	}

	assert.Equal(t, 1, wins, "exactly one CAS winner expected; got %d", wins)

	got, getErr := rs.GetByHash(ctx, hashReset("toctou-reset-token"))
	require.NoError(t, getErr)
	assert.NotNil(t, got.UsedAt, "used_at must be set by the CAS winner")
}

// TestTxManager_WithResetTx_Integration covers the atomic transaction:
// MarkUsed + SetPasswordHash + BumpTokenVersion must all commit together, or
// all roll back on error. This mirrors TestTxManager_RegisterAtomic_Integration.
func TestTxManager_WithResetTx_Integration(t *testing.T) {
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
	rs := postgres.NewPasswordResetStore(pool)

	t.Run("commit: MarkUsed + SetPasswordHash + BumpTokenVersion all persist", func(t *testing.T) {
		u := seedActiveUserForReset(t, ctx, us, "reset-tx-commit@integration.test")

		rt := &domain.PasswordResetToken{
			ID:        uuid.New(),
			UserID:    u.ID,
			TokenHash: hashReset("tx-reset-good"),
			ExpiresAt: time.Now().UTC().Add(30 * time.Minute),
			CreatedAt: time.Now().UTC(),
		}
		require.NoError(t, rs.Create(ctx, rt))

		newHash := "$argon2id$v=19$m=65536,t=3,p=2$newSalt$newHash"

		err := txMgr.WithResetTx(ctx, func(txCtx context.Context, users store.UserStore, resets store.PasswordResetTokenStore) error {
			if e := resets.MarkUsed(txCtx, rt.ID, time.Now().UTC()); e != nil {
				return e
			}
			if e := users.SetPasswordHash(txCtx, u.ID, newHash); e != nil {
				return e
			}
			_, e := users.BumpTokenVersion(txCtx, u.ID)

			return e
		})
		require.NoError(t, err)

		// Verify token was marked used.
		got, err := rs.GetByHash(ctx, hashReset("tx-reset-good"))
		require.NoError(t, err)
		assert.NotNil(t, got.UsedAt, "token must be marked used after commit")

		// Verify password hash was updated.
		gotUser, err := us.GetByID(ctx, u.ID)
		require.NoError(t, err)
		require.NotNil(t, gotUser.PasswordHash)
		assert.Equal(t, newHash, *gotUser.PasswordHash, "password hash must be updated after commit")

		// Verify token_version was bumped.
		assert.Greater(t, gotUser.TokenVersion, u.TokenVersion, "token_version must be bumped")
	})

	t.Run("rollback: none of MarkUsed/SetPasswordHash/BumpTokenVersion persist", func(t *testing.T) {
		u := seedActiveUserForReset(t, ctx, us, "reset-tx-rollback@integration.test")
		originalHash := u.PasswordHash
		originalVersion := u.TokenVersion

		rt := &domain.PasswordResetToken{
			ID:        uuid.New(),
			UserID:    u.ID,
			TokenHash: hashReset("tx-reset-rollback"),
			ExpiresAt: time.Now().UTC().Add(30 * time.Minute),
			CreatedAt: time.Now().UTC(),
		}
		require.NoError(t, rs.Create(ctx, rt))

		sentinel := assertErr("forced rollback")

		err := txMgr.WithResetTx(ctx, func(txCtx context.Context, users store.UserStore, resets store.PasswordResetTokenStore) error {
			if e := resets.MarkUsed(txCtx, rt.ID, time.Now().UTC()); e != nil {
				return e
			}
			if e := users.SetPasswordHash(txCtx, u.ID, "new-hash-that-should-not-persist"); e != nil {
				return e
			}

			return sentinel
		})
		require.ErrorIs(t, err, sentinel)

		// Token must still be unused.
		gotTok, err := rs.GetByHash(ctx, hashReset("tx-reset-rollback"))
		require.NoError(t, err)
		assert.Nil(t, gotTok.UsedAt, "token must remain unused after rollback")

		// Password hash must be unchanged.
		gotUser, err := us.GetByID(ctx, u.ID)
		require.NoError(t, err)
		assert.Equal(t, originalHash, gotUser.PasswordHash, "password hash must not change after rollback")
		assert.Equal(t, originalVersion, gotUser.TokenVersion, "token_version must not change after rollback")
	})
}

// TestUserStore_SetPasswordHash_Integration verifies SetPasswordHash in UserStore.
func TestUserStore_SetPasswordHash_Integration(t *testing.T) {
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

	t.Run("happy path: password hash updated and persisted", func(t *testing.T) {
		u := seedActiveUserForReset(t, ctx, us, "set-pw-hash@integration.test")

		newHash := "$argon2id$v=19$m=65536,t=3,p=2$changedsalt$changedhash"
		require.NoError(t, us.SetPasswordHash(ctx, u.ID, newHash))

		got, err := us.GetByID(ctx, u.ID)
		require.NoError(t, err)
		require.NotNil(t, got.PasswordHash)
		assert.Equal(t, newHash, *got.PasswordHash)
	})

	t.Run("unknown user returns ErrNotFound", func(t *testing.T) {
		err := us.SetPasswordHash(ctx, uuid.New(), "some-hash")
		require.ErrorIs(t, err, domain.ErrNotFound)
	})
}
