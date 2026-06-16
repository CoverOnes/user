package postgres_test

import (
	"context"
	"testing"
	"time"

	"github.com/CoverOnes/user/internal/domain"
	"github.com/CoverOnes/user/internal/store"
	"github.com/CoverOnes/user/internal/store/postgres"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func sp(s string) *string { return &s }

// seedUser inserts a minimal ACTIVE user and returns it.
func seedUser(t *testing.T, ctx context.Context, st *postgres.UserStore, email string) *domain.User {
	t.Helper()

	now := time.Now().UTC().Truncate(time.Millisecond)
	u := &domain.User{
		ID:           uuid.New(),
		Email:        email,
		PasswordHash: testPH(),
		DisplayName:  "Seed",
		AccountType:  "PERSONAL",
		KYCTier:      0,
		Status:       "ACTIVE",
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	require.NoError(t, st.Create(ctx, u))

	return u
}

// TestUserStore_PublicProfile_Integration exercises migration 000009's new columns
// and the users_handle_unique partial index against a REAL Postgres (testcontainers).
// Covers: full-replace round-trip of all 5 public columns, citext case-insensitive
// handle uniqueness (23505 → ErrHandleTaken), clear-on-nil, NotFound, and that a
// soft-deleted row frees its handle for re-use.
func TestUserStore_PublicProfile_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ctx := context.Background()
	dsn := startTestDB(t)
	runMigrations(t, ctx, dsn, "")

	pool, err := postgres.NewPool(ctx, dsn, "", 0, 0)
	require.NoError(t, err)

	defer pool.Close()

	st := postgres.NewUserStore(pool)

	t.Run("full replace round-trips all public columns", func(t *testing.T) {
		u := seedUser(t, ctx, st, "round-trip@profile.test")

		in := store.ProfileUpdate{
			DisplayName: "Round Trip",
			Handle:      sp("roundtrip"),
			Headline:    sp("Senior Engineer"),
			Bio:         sp("About me"),
			Location:    sp("Taipei"),
			AvatarURL:   sp("https://cdn.example.com/a.png"),
			CoverURL:    sp("https://cdn.example.com/c.png"),
		}
		require.NoError(t, st.UpdateProfile(ctx, u.ID, in))

		got, err := st.GetByID(ctx, u.ID)
		require.NoError(t, err)
		assert.Equal(t, "Round Trip", got.DisplayName)
		require.NotNil(t, got.Handle)
		assert.Equal(t, "roundtrip", *got.Handle)
		require.NotNil(t, got.Headline)
		assert.Equal(t, "Senior Engineer", *got.Headline)
		require.NotNil(t, got.Bio)
		assert.Equal(t, "About me", *got.Bio)
		require.NotNil(t, got.Location)
		assert.Equal(t, "Taipei", *got.Location)
		require.NotNil(t, got.CoverURL)
		assert.Equal(t, "https://cdn.example.com/c.png", *got.CoverURL)
	})

	t.Run("nil fields clear the columns (full replace semantics)", func(t *testing.T) {
		u := seedUser(t, ctx, st, "clear@profile.test")

		// First set everything.
		require.NoError(t, st.UpdateProfile(ctx, u.ID, store.ProfileUpdate{
			DisplayName: "Has Data",
			Handle:      sp("hasdata"),
			Headline:    sp("h"),
			Bio:         sp("b"),
			Location:    sp("l"),
			CoverURL:    sp("https://cdn.example.com/x.png"),
		}))

		// Then clear with a nil-everything update.
		require.NoError(t, st.UpdateProfile(ctx, u.ID, store.ProfileUpdate{DisplayName: "Cleared"}))

		got, err := st.GetByID(ctx, u.ID)
		require.NoError(t, err)
		assert.Equal(t, "Cleared", got.DisplayName)
		assert.Nil(t, got.Handle)
		assert.Nil(t, got.Headline)
		assert.Nil(t, got.Bio)
		assert.Nil(t, got.Location)
		assert.Nil(t, got.CoverURL)
	})

	t.Run("duplicate handle (case-insensitive) returns ErrHandleTaken", func(t *testing.T) {
		a := seedUser(t, ctx, st, "dup-a@profile.test")
		b := seedUser(t, ctx, st, "dup-b@profile.test")

		require.NoError(t, st.UpdateProfile(ctx, a.ID, store.ProfileUpdate{
			DisplayName: "A", Handle: sp("uniquehandle"),
		}))

		// B claims the same handle in a different case — citext makes it collide.
		err := st.UpdateProfile(ctx, b.ID, store.ProfileUpdate{
			DisplayName: "B", Handle: sp("UNIQUEHANDLE"),
		})
		require.ErrorIs(t, err, domain.ErrHandleTaken)
	})

	t.Run("same user can re-set its own handle (no self-conflict)", func(t *testing.T) {
		u := seedUser(t, ctx, st, "self@profile.test")

		require.NoError(t, st.UpdateProfile(ctx, u.ID, store.ProfileUpdate{
			DisplayName: "Self", Handle: sp("selfhandle"),
		}))
		// Re-applying the same handle must not 23505 against its own row.
		require.NoError(t, st.UpdateProfile(ctx, u.ID, store.ProfileUpdate{
			DisplayName: "Self2", Handle: sp("selfhandle"),
		}))
	})

	t.Run("update on non-existent user returns ErrNotFound", func(t *testing.T) {
		err := st.UpdateProfile(ctx, uuid.New(), store.ProfileUpdate{DisplayName: "Ghost"})
		require.ErrorIs(t, err, domain.ErrNotFound)
	})

	t.Run("soft-deleted row frees its handle (partial index)", func(t *testing.T) {
		owner := seedUser(t, ctx, st, "owner@profile.test")
		require.NoError(t, st.UpdateProfile(ctx, owner.ID, store.ProfileUpdate{
			DisplayName: "Owner", Handle: sp("freeable"),
		}))

		// Soft-delete the owner directly (no store method exists for this).
		_, err := pool.Exec(ctx, `UPDATE users SET deleted_at = now() WHERE id = $1`, owner.ID)
		require.NoError(t, err)

		// A NEW live user can now claim the freed handle — the partial unique index
		// (WHERE deleted_at IS NULL) no longer counts the soft-deleted row.
		newcomer := seedUser(t, ctx, st, "newcomer@profile.test")
		require.NoError(t, st.UpdateProfile(ctx, newcomer.ID, store.ProfileUpdate{
			DisplayName: "Newcomer", Handle: sp("freeable"),
		}), "soft-deleted owner must free its handle for re-use")

		got, err := st.GetByID(ctx, newcomer.ID)
		require.NoError(t, err)
		require.NotNil(t, got.Handle)
		assert.Equal(t, "freeable", *got.Handle)
	})
}
