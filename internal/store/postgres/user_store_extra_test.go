package postgres_test

import (
	"context"
	"testing"
	"time"

	"github.com/CoverOnes/user/internal/domain"
	"github.com/CoverOnes/user/internal/store/postgres"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestUserStore_UpdateKYCTier_Integration verifies UpdateKYCTier against real Postgres.
func TestUserStore_UpdateKYCTier_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ctx := context.Background()
	dsn := startTestDB(t)
	runMigrations(t, ctx, dsn, "")

	pool, err := postgres.NewPool(ctx, dsn, "", 0, 0)
	require.NoError(t, err)

	defer pool.Close()

	userStore := postgres.NewUserStore(pool)

	t.Run("update kyc_tier happy path", func(t *testing.T) {
		now := time.Now().UTC().Truncate(time.Millisecond)
		u := &domain.User{
			ID:           uuid.New(),
			Email:        "kyc-tier-update@example.test",
			PasswordHash: testPasswordHash,
			DisplayName:  "KYC Test",
			AccountType:  "PERSONAL",
			KYCTier:      0,
			Status:       "ACTIVE",
			TokenVersion: 0,
			CreatedAt:    now,
			UpdatedAt:    now,
		}

		require.NoError(t, userStore.Create(ctx, u))

		require.NoError(t, userStore.UpdateKYCTier(ctx, u.ID, 2))

		got, err := userStore.GetByID(ctx, u.ID)
		require.NoError(t, err)
		assert.Equal(t, int16(2), got.KYCTier)
	})

	t.Run("update kyc_tier on non-existent user returns ErrNotFound", func(t *testing.T) {
		err := userStore.UpdateKYCTier(ctx, uuid.New(), 1)
		require.ErrorIs(t, err, domain.ErrNotFound)
	})

	t.Run("update kyc_tier multiple times accumulates correctly", func(t *testing.T) {
		now := time.Now().UTC().Truncate(time.Millisecond)
		u := &domain.User{
			ID:           uuid.New(),
			Email:        "kyc-multi@example.test",
			PasswordHash: testPasswordHash,
			DisplayName:  "Multi",
			AccountType:  "PERSONAL",
			KYCTier:      0,
			Status:       "ACTIVE",
			CreatedAt:    now,
			UpdatedAt:    now,
		}

		require.NoError(t, userStore.Create(ctx, u))

		require.NoError(t, userStore.UpdateKYCTier(ctx, u.ID, 1))
		require.NoError(t, userStore.UpdateKYCTier(ctx, u.ID, 3))

		got, err := userStore.GetByID(ctx, u.ID)
		require.NoError(t, err)
		assert.Equal(t, int16(3), got.KYCTier)
	})
}

// TestUserStore_BumpTokenVersion_Integration verifies BumpTokenVersion against real Postgres.
func TestUserStore_BumpTokenVersion_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ctx := context.Background()
	dsn := startTestDB(t)
	runMigrations(t, ctx, dsn, "")

	pool, err := postgres.NewPool(ctx, dsn, "", 0, 0)
	require.NoError(t, err)

	defer pool.Close()

	userStore := postgres.NewUserStore(pool)

	t.Run("bump token version returns new value", func(t *testing.T) {
		now := time.Now().UTC().Truncate(time.Millisecond)
		u := &domain.User{
			ID:           uuid.New(),
			Email:        "bump-version@example.test",
			PasswordHash: testPasswordHash,
			DisplayName:  "Bump",
			AccountType:  "PERSONAL",
			KYCTier:      0,
			Status:       "ACTIVE",
			TokenVersion: 0,
			CreatedAt:    now,
			UpdatedAt:    now,
		}

		require.NoError(t, userStore.Create(ctx, u))

		v1, err := userStore.BumpTokenVersion(ctx, u.ID)
		require.NoError(t, err)
		assert.Equal(t, 1, v1)

		v2, err := userStore.BumpTokenVersion(ctx, u.ID)
		require.NoError(t, err)
		assert.Equal(t, 2, v2)

		got, err := userStore.GetByID(ctx, u.ID)
		require.NoError(t, err)
		assert.Equal(t, 2, got.TokenVersion)
	})

	t.Run("bump token version on non-existent user returns ErrNotFound", func(t *testing.T) {
		_, err := userStore.BumpTokenVersion(ctx, uuid.New())
		require.ErrorIs(t, err, domain.ErrNotFound)
	})
}
