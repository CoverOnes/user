package postgres_test

import (
	"context"
	"fmt"
	"io/fs"
	"net/netip"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/CoverOnes/user/internal/domain"
	"github.com/CoverOnes/user/internal/store/postgres"
	migrations "github.com/CoverOnes/user/migrations"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
)

// testPasswordHash is a fake argon2id hash used as a placeholder in test fixtures.
// It is not a real credential — the value is a structurally-valid but inert hash for schema compatibility only.
const testPasswordHash = "$argon2id$v=19$m=65536,t=3,p=2$abc$def" //nolint:gosec // G101: test fixture, not a real credential

// startTestDB spins up a real Postgres container via testcontainers.
func startTestDB(t *testing.T) string {
	t.Helper()

	ctx := context.Background()

	ctr, err := tcpostgres.Run(ctx,
		"postgres:17-alpine",
		tcpostgres.WithDatabase("testdb"),
		tcpostgres.WithUsername("testuser"),
		tcpostgres.WithPassword("testpass"),
		tcpostgres.BasicWaitStrategies(),
	)
	require.NoError(t, err)

	t.Cleanup(func() {
		if termErr := ctr.Terminate(ctx); termErr != nil {
			t.Logf("terminate container: %v", termErr)
		}
	})

	dsn, err := ctr.ConnectionString(ctx, "sslmode=disable")
	require.NoError(t, err)

	return dsn
}

// runMigrations applies the embedded *.up.sql migration files against the test DB (F15).
// Using the real migration files ensures schema drift is caught immediately.
func runMigrations(t *testing.T, ctx context.Context, dsn string) {
	t.Helper()

	pool, err := postgres.NewPool(ctx, dsn)
	require.NoError(t, err)

	defer pool.Close()

	// Collect all *.up.sql files from the embedded FS and sort them for deterministic order.
	var upFiles []string

	err = fs.WalkDir(migrations.FS, ".", func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if !d.IsDir() && strings.HasSuffix(path, ".up.sql") {
			upFiles = append(upFiles, path)
		}
		return nil
	})
	require.NoError(t, err, "walk embedded migrations FS")
	require.NotEmpty(t, upFiles, "no *.up.sql files found in embedded FS")

	sort.Strings(upFiles)

	for _, file := range upFiles {
		data, readErr := migrations.FS.ReadFile(file)
		require.NoError(t, readErr, "read migration file %s", file)

		_, execErr := pool.Exec(ctx, string(data))
		require.NoError(t, execErr, fmt.Sprintf("apply migration %s", file))
	}
}

// TestUserStore_Integration tests the UserStore against a real Postgres instance.
func TestUserStore_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ctx := context.Background()
	dsn := startTestDB(t)
	runMigrations(t, ctx, dsn)

	pool, err := postgres.NewPool(ctx, dsn)
	require.NoError(t, err)

	defer pool.Close()

	userStore := postgres.NewUserStore(pool)

	t.Run("create and get by ID", func(t *testing.T) {
		now := time.Now().UTC().Truncate(time.Millisecond)
		u := &domain.User{
			ID:           uuid.New(),
			Email:        "alice@integration.test",
			PasswordHash: testPasswordHash,
			DisplayName:  "Alice",
			AccountType:  "PERSONAL",
			KYCTier:      0,
			Status:       "ACTIVE",
			TokenVersion: 0,
			CreatedAt:    now,
			UpdatedAt:    now,
		}

		require.NoError(t, userStore.Create(ctx, u))

		got, err := userStore.GetByID(ctx, u.ID)
		require.NoError(t, err)
		assert.Equal(t, u.ID, got.ID)
		assert.Equal(t, u.Email, got.Email)
		assert.Equal(t, u.DisplayName, got.DisplayName)
	})

	t.Run("get by email", func(t *testing.T) {
		now := time.Now().UTC().Truncate(time.Millisecond)
		u := &domain.User{
			ID:           uuid.New(),
			Email:        "bob@integration.test",
			PasswordHash: testPasswordHash,
			DisplayName:  "Bob",
			AccountType:  "PERSONAL",
			KYCTier:      0,
			Status:       "ACTIVE",
			CreatedAt:    now,
			UpdatedAt:    now,
		}

		require.NoError(t, userStore.Create(ctx, u))

		got, err := userStore.GetByEmail(ctx, "bob@integration.test")
		require.NoError(t, err)
		assert.Equal(t, u.ID, got.ID)
	})

	t.Run("get by email case insensitive (citext)", func(t *testing.T) {
		now := time.Now().UTC().Truncate(time.Millisecond)
		u := &domain.User{
			ID:           uuid.New(),
			Email:        "carol@integration.test",
			PasswordHash: testPasswordHash,
			DisplayName:  "Carol",
			AccountType:  "PERSONAL",
			KYCTier:      0,
			Status:       "ACTIVE",
			CreatedAt:    now,
			UpdatedAt:    now,
		}

		require.NoError(t, userStore.Create(ctx, u))

		// citext column makes this case-insensitive.
		got, err := userStore.GetByEmail(ctx, "CAROL@INTEGRATION.TEST")
		require.NoError(t, err)
		assert.Equal(t, u.ID, got.ID)
	})

	t.Run("duplicate email returns ErrEmailTaken", func(t *testing.T) {
		now := time.Now().UTC().Truncate(time.Millisecond)
		u := &domain.User{
			ID:           uuid.New(),
			Email:        "dup@integration.test",
			PasswordHash: testPasswordHash,
			DisplayName:  "Dup",
			AccountType:  "PERSONAL",
			KYCTier:      0,
			Status:       "ACTIVE",
			CreatedAt:    now,
			UpdatedAt:    now,
		}

		require.NoError(t, userStore.Create(ctx, u))

		u2 := *u
		u2.ID = uuid.New()
		err := userStore.Create(ctx, &u2)
		require.ErrorIs(t, err, domain.ErrEmailTaken)
	})

	t.Run("get by ID not found", func(t *testing.T) {
		_, err := userStore.GetByID(ctx, uuid.New())
		require.ErrorIs(t, err, domain.ErrNotFound)
	})

	t.Run("update profile", func(t *testing.T) {
		now := time.Now().UTC().Truncate(time.Millisecond)
		u := &domain.User{
			ID:           uuid.New(),
			Email:        "dave@integration.test",
			PasswordHash: testPasswordHash,
			DisplayName:  "Dave",
			AccountType:  "PERSONAL",
			KYCTier:      0,
			Status:       "ACTIVE",
			CreatedAt:    now,
			UpdatedAt:    now,
		}

		require.NoError(t, userStore.Create(ctx, u))

		newName := "Dave Updated"
		require.NoError(t, userStore.UpdateProfile(ctx, u.ID, newName, nil))

		got, err := userStore.GetByID(ctx, u.ID)
		require.NoError(t, err)
		assert.Equal(t, newName, got.DisplayName)
	})
}

// TestRefreshTokenStore_Integration tests refresh token lifecycle against real Postgres.
func TestRefreshTokenStore_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ctx := context.Background()
	dsn := startTestDB(t)
	runMigrations(t, ctx, dsn)

	pool, err := postgres.NewPool(ctx, dsn)
	require.NoError(t, err)

	defer pool.Close()

	rtStore := postgres.NewRefreshTokenStore(pool)

	t.Run("create and get by ID", func(t *testing.T) {
		userID := uuid.New()
		familyID := uuid.New()
		rtID1 := uuid.New()
		rt := &domain.RefreshToken{
			ID:        rtID1,
			UserID:    userID,
			FamilyID:  familyID,
			TokenHash: rtID1[:], // unique per test run
			ExpiresAt: time.Now().UTC().Add(24 * time.Hour),
			CreatedAt: time.Now().UTC(),
		}

		require.NoError(t, rtStore.Create(ctx, rt))

		got, err := rtStore.GetByID(ctx, rt.ID)
		require.NoError(t, err)
		assert.Equal(t, rt.ID, got.ID)
		assert.Equal(t, rt.UserID, got.UserID)
		assert.Equal(t, rt.FamilyID, got.FamilyID)
		assert.Nil(t, got.UsedAt)
		assert.Nil(t, got.RevokedAt)
	})

	t.Run("mark used", func(t *testing.T) {
		id2 := uuid.New()
		rt := &domain.RefreshToken{
			ID:        id2,
			UserID:    uuid.New(),
			FamilyID:  uuid.New(),
			TokenHash: id2[:], // use the UUID bytes as a unique hash
			ExpiresAt: time.Now().UTC().Add(24 * time.Hour),
			CreatedAt: time.Now().UTC(),
		}

		require.NoError(t, rtStore.Create(ctx, rt))

		now := time.Now().UTC()
		require.NoError(t, rtStore.MarkUsed(ctx, rt.ID, now))

		got, err := rtStore.GetByID(ctx, rt.ID)
		require.NoError(t, err)
		assert.NotNil(t, got.UsedAt)
		assert.NotNil(t, got.RevokedAt)
	})

	t.Run("revoke family", func(t *testing.T) {
		familyID := uuid.New()
		userID := uuid.New()

		rt1 := &domain.RefreshToken{
			ID:        uuid.New(),
			UserID:    userID,
			FamilyID:  familyID,
			TokenHash: []byte{0x01, 0x02},
			ExpiresAt: time.Now().UTC().Add(24 * time.Hour),
			CreatedAt: time.Now().UTC(),
		}
		rt2 := &domain.RefreshToken{
			ID:        uuid.New(),
			UserID:    userID,
			FamilyID:  familyID,
			TokenHash: []byte{0x03, 0x04},
			ExpiresAt: time.Now().UTC().Add(24 * time.Hour),
			CreatedAt: time.Now().UTC(),
		}

		require.NoError(t, rtStore.Create(ctx, rt1))
		require.NoError(t, rtStore.Create(ctx, rt2))

		now := time.Now().UTC()
		require.NoError(t, rtStore.RevokeFamily(ctx, familyID, now))

		got1, err := rtStore.GetByID(ctx, rt1.ID)
		require.NoError(t, err)
		assert.NotNil(t, got1.RevokedAt)

		got2, err := rtStore.GetByID(ctx, rt2.ID)
		require.NoError(t, err)
		assert.NotNil(t, got2.RevokedAt)
	})

	t.Run("get nonexistent returns ErrInvalidRefresh", func(t *testing.T) {
		_, err := rtStore.GetByID(ctx, uuid.New())
		require.ErrorIs(t, err, domain.ErrInvalidRefresh)
	})

	t.Run("with ip address", func(t *testing.T) {
		id5 := uuid.New()
		rt := &domain.RefreshToken{
			ID:        id5,
			UserID:    uuid.New(),
			FamilyID:  uuid.New(),
			TokenHash: id5[:], // use the UUID bytes as a unique hash
			IPAddr:    netip.MustParseAddr("192.168.1.100"),
			ExpiresAt: time.Now().UTC().Add(24 * time.Hour),
			CreatedAt: time.Now().UTC(),
		}

		require.NoError(t, rtStore.Create(ctx, rt))

		got, err := rtStore.GetByID(ctx, rt.ID)
		require.NoError(t, err)
		assert.Equal(t, "192.168.1.100", got.IPAddr.String())
	})
}
