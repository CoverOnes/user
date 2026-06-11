package postgres_test

import (
	"context"
	"fmt"
	"io/fs"
	"net/netip"
	"sort"
	"strings"
	"sync"
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

// testPH is a *string pointing at testPasswordHash for use in domain.User struct literals
// where PasswordHash is nullable since migration 000007.
func testPH() *string { s := testPasswordHash; return &s }

// startTestDB spins up a real Postgres container via testcontainers.
func startTestDB(t *testing.T) string {
	t.Helper()

	ctx := context.Background()

	ctr, err := tcpostgres.Run(
		ctx,
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
// schema may be "" (public) or a custom schema name validated by config.
func runMigrations(t *testing.T, ctx context.Context, dsn, schema string) {
	t.Helper()

	pool, err := postgres.NewPool(ctx, dsn, schema, 0, 0) // 0 → defaults (10/2)
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
	runMigrations(t, ctx, dsn, "") // empty schema = public (test default)

	pool, err := postgres.NewPool(ctx, dsn, "", 0, 0) // empty schema = public (test default)
	require.NoError(t, err)

	defer pool.Close()

	userStore := postgres.NewUserStore(pool)

	t.Run("create and get by ID", func(t *testing.T) {
		now := time.Now().UTC().Truncate(time.Millisecond)
		u := &domain.User{
			ID:           uuid.New(),
			Email:        "alice@integration.test",
			PasswordHash: testPH(),
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
			PasswordHash: testPH(),
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
			PasswordHash: testPH(),
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
			PasswordHash: testPH(),
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
			PasswordHash: testPH(),
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

// TestPool_SchemaIsolation verifies that when a non-empty schema is provided to NewPool,
// CREATE SCHEMA IF NOT EXISTS is executed and all migrations land in that schema
// (not in "public"). It checks information_schema.tables to assert table_schema.
func TestPool_SchemaIsolation(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	const testSchema = "dev_test_schema"

	ctx := context.Background()
	dsn := startTestDB(t)

	// Build pool with the custom schema — this must CREATE SCHEMA IF NOT EXISTS
	// and set search_path on every connection.
	runMigrations(t, ctx, dsn, testSchema)

	pool, err := postgres.NewPool(ctx, dsn, testSchema, 0, 0)
	require.NoError(t, err)

	defer pool.Close()

	// Assert that the users table exists in the custom schema via information_schema.
	var count int
	err = pool.QueryRow(
		ctx,
		"SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = $1 AND table_name = 'users'",
		testSchema,
	).Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 1, count, "users table must exist in schema %q after migrations", testSchema)

	// Also assert the table does NOT exist in public (isolation check).
	var publicCount int
	err = pool.QueryRow(
		ctx,
		"SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'users'",
	).Scan(&publicCount)
	require.NoError(t, err)
	assert.Equal(t, 0, publicCount, "users table must NOT exist in public schema when using custom schema")
}

// TestRefreshTokenStore_Integration tests refresh token lifecycle against real Postgres.
func TestRefreshTokenStore_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ctx := context.Background()
	dsn := startTestDB(t)
	runMigrations(t, ctx, dsn, "") // empty schema = public (test default)

	pool, err := postgres.NewPool(ctx, dsn, "", 0, 0) // empty schema = public (test default)
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
		ok, err := rtStore.MarkUsed(ctx, rt.ID, now)
		require.NoError(t, err)
		assert.True(t, ok, "first MarkUsed must flip the row (CAS win)")

		got, err := rtStore.GetByID(ctx, rt.ID)
		require.NoError(t, err)
		assert.NotNil(t, got.UsedAt)
		assert.NotNil(t, got.RevokedAt)

		// CAS: second MarkUsed on the same token must return ok=false (already used).
		ok2, err2 := rtStore.MarkUsed(ctx, rt.ID, now)
		require.NoError(t, err2)
		assert.False(t, ok2, "second MarkUsed must return false (CAS guard: used_at IS NOT NULL)")
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

// TestPool_ReservedWordSchema verifies that NewPool correctly handles a schema
// name that is a PostgreSQL reserved word (e.g. "user").
//
// Before the fix, raw string concatenation in the SET search_path and CREATE SCHEMA
// statements caused PG error 42601 (syntax_error) at runtime. The fix uses
// pgx.Identifier.Sanitize() to produce a properly double-quoted identifier.
func TestPool_ReservedWordSchema(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	// "user" is a PostgreSQL reserved word — raw concatenation would produce
	//   SET search_path = user, public       → 42601 syntax error
	//   CREATE SCHEMA IF NOT EXISTS user     → 42601 syntax error
	// With quoting it becomes:
	//   SET search_path = "user", public     → OK
	//   CREATE SCHEMA IF NOT EXISTS "user"   → OK
	const reservedSchema = "user"

	ctx := context.Background()
	dsn := startTestDB(t)

	// NewPool must not error on a reserved-word schema name.
	runMigrations(t, ctx, dsn, reservedSchema)

	pool, err := postgres.NewPool(ctx, dsn, reservedSchema, 0, 0)
	require.NoError(t, err, "NewPool must succeed with reserved-word schema %q", reservedSchema)

	defer pool.Close()

	// The schema must exist in pg_namespace.
	var schemaExists bool

	err = pool.QueryRow(
		ctx,
		"SELECT EXISTS(SELECT 1 FROM information_schema.schemata WHERE schema_name = $1)",
		reservedSchema,
	).Scan(&schemaExists)
	require.NoError(t, err)
	assert.True(t, schemaExists, "schema %q must exist in information_schema.schemata", reservedSchema)

	// The service's main table (users) must be in the "user" schema, not in public.
	var count int

	err = pool.QueryRow(
		ctx,
		"SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = $1 AND table_name = 'users'",
		reservedSchema,
	).Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 1, count, "users table must exist in the %q schema", reservedSchema)

	// Verify that search_path is active: a bare table reference must resolve to
	// the "user" schema, not to public.
	var currentSchema string

	err = pool.QueryRow(ctx, "SELECT current_schema()").Scan(&currentSchema)
	require.NoError(t, err)
	assert.Equal(t, reservedSchema, currentSchema, "current_schema() must return %q when search_path is set", reservedSchema)
}

// TestRefreshTokenStore_MarkUsed_TOCTOU_Integration is the decisive concurrency
// test for the CAS-based reuse detection (audit finding: refresh-token rotation
// TOCTOU). Two goroutines race to call MarkUsed on the same valid token
// simultaneously. The Postgres-level CAS (WHERE used_at IS NULL) ensures EXACTLY
// ONE wins; the loser receives ok=false, so the caller can revoke the family and
// return ErrRefreshReuse. This test cannot be expressed with an in-memory fake
// because the race is in the DB serialization layer.
func TestRefreshTokenStore_MarkUsed_TOCTOU_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ctx := context.Background()
	dsn := startTestDB(t)
	runMigrations(t, ctx, dsn, "")

	pool, err := postgres.NewPool(ctx, dsn, "", 0, 0)
	require.NoError(t, err)

	defer pool.Close()

	rtStore := postgres.NewRefreshTokenStore(pool)

	// Seed a fresh, unused token.
	rtID := uuid.New()
	rt := &domain.RefreshToken{
		ID:        rtID,
		UserID:    uuid.New(),
		FamilyID:  uuid.New(),
		TokenHash: rtID[:],
		ExpiresAt: time.Now().UTC().Add(24 * time.Hour),
		CreatedAt: time.Now().UTC(),
	}
	require.NoError(t, rtStore.Create(ctx, rt))

	now := time.Now().UTC()

	const goroutines = 10

	results := make([]bool, goroutines)

	var wg sync.WaitGroup
	start := make(chan struct{}) // synchronized launch

	for i := range goroutines {
		wg.Add(1)

		go func(idx int) {
			defer wg.Done()

			<-start // wait for all goroutines to be ready

			ok, err := rtStore.MarkUsed(ctx, rtID, now)
			if err != nil {
				// Unexpected DB error — treat as a lose so the assertion below
				// still counts correctly.
				t.Logf("goroutine %d: MarkUsed error: %v", idx, err)
				results[idx] = false

				return
			}

			results[idx] = ok
		}(i)
	}

	close(start) // release all goroutines simultaneously
	wg.Wait()

	// Exactly one goroutine must have won the CAS.
	wins := 0

	for _, ok := range results {
		if ok {
			wins++
		}
	}

	assert.Equal(t, 1, wins, "exactly one CAS winner expected; got %d (concurrent MarkUsed race not serialized correctly)", wins)

	// The winning goroutine must have actually set used_at in the DB.
	got, err := rtStore.GetByID(ctx, rtID)
	require.NoError(t, err)
	assert.NotNil(t, got.UsedAt, "used_at must be set after the CAS winner")
	assert.NotNil(t, got.RevokedAt, "revoked_at must be set after the CAS winner")
}

// TestUserStore_UpdateKYCTier_Monotonic_Integration verifies that UpdateKYCTier
// is monotonic: it never lowers kyc_tier and silently absorbs stale/replayed events.
func TestUserStore_UpdateKYCTier_Monotonic_Integration(t *testing.T) {
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

	// Seed a user at tier 0.
	now := time.Now().UTC().Truncate(time.Millisecond)
	u := &domain.User{
		ID:           uuid.New(),
		Email:        "kyc-monotonic@integration.test",
		PasswordHash: testPH(),
		DisplayName:  "Mono",
		AccountType:  "PERSONAL",
		KYCTier:      0,
		Status:       "ACTIVE",
		TokenVersion: 0,
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	require.NoError(t, userStore.Create(ctx, u))

	t.Run("tier advances normally", func(t *testing.T) {
		require.NoError(t, userStore.UpdateKYCTier(ctx, u.ID, 2))

		got, err := userStore.GetByID(ctx, u.ID)
		require.NoError(t, err)
		assert.Equal(t, int16(2), got.KYCTier, "tier must be advanced to 2")
	})

	t.Run("equal tier is a no-op (idempotent)", func(t *testing.T) {
		// Already at 2; publishing tier=2 again must not error and tier stays 2.
		require.NoError(t, userStore.UpdateKYCTier(ctx, u.ID, 2))

		got, err := userStore.GetByID(ctx, u.ID)
		require.NoError(t, err)
		assert.Equal(t, int16(2), got.KYCTier, "tier must remain 2 after same-tier update")
	})

	t.Run("lower tier is silently ignored (replay protection)", func(t *testing.T) {
		// Attempt to roll back to tier 1 (e.g. a replayed old event).
		require.NoError(t, userStore.UpdateKYCTier(ctx, u.ID, 1),
			"stale event must return nil, not an error")

		got, err := userStore.GetByID(ctx, u.ID)
		require.NoError(t, err)
		assert.Equal(t, int16(2), got.KYCTier, "tier must NOT be lowered by a stale event")
	})

	t.Run("unknown user returns ErrNotFound", func(t *testing.T) {
		err := userStore.UpdateKYCTier(ctx, uuid.New(), 1)
		require.ErrorIs(t, err, domain.ErrNotFound, "unknown user must return ErrNotFound")
	})
}
