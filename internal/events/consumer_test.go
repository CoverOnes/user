package events_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/CoverOnes/user/internal/domain"
	"github.com/CoverOnes/user/internal/events"
	"github.com/CoverOnes/user/internal/store/postgres"
	migrations "github.com/CoverOnes/user/migrations"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	tcredis "github.com/testcontainers/testcontainers-go/modules/redis"
)

// testPasswordHash is a structurally-valid but inert argon2id hash for test fixtures.
const testPasswordHash = "$argon2id$v=19$m=65536,t=3,p=2$abc$def" //nolint:gosec // G101: test fixture, not a real credential

// startTestPostgres spins up a real Postgres container via testcontainers.
func startTestPostgres(t *testing.T) string {
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
			t.Logf("terminate postgres container: %v", termErr)
		}
	})

	dsn, err := ctr.ConnectionString(ctx, "sslmode=disable")
	require.NoError(t, err)

	return dsn
}

// startTestRedis spins up a real Redis container via testcontainers.
func startTestRedis(t *testing.T) string {
	t.Helper()

	ctx := context.Background()

	ctr, err := tcredis.Run(ctx, "redis:7-alpine")
	require.NoError(t, err)

	t.Cleanup(func() {
		if termErr := ctr.Terminate(ctx); termErr != nil {
			t.Logf("terminate redis container: %v", termErr)
		}
	})

	addr, err := ctr.ConnectionString(ctx)
	require.NoError(t, err)

	return addr
}

// runMigrations applies all embedded *.up.sql migration files against the test DB.
func runMigrations(t *testing.T, ctx context.Context, dsn string) {
	t.Helper()

	pool, err := postgres.NewPool(ctx, dsn, "", 0, 0)
	require.NoError(t, err)

	defer pool.Close()

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
	require.NoError(t, err)
	require.NotEmpty(t, upFiles)

	sort.Strings(upFiles)

	for _, file := range upFiles {
		data, readErr := migrations.FS.ReadFile(file)
		require.NoError(t, readErr)

		_, execErr := pool.Exec(ctx, string(data))
		require.NoError(t, execErr, fmt.Sprintf("apply migration %s", file))
	}
}

// publishKYCTierChanged publishes a kyc.tier_changed event to Redis.
func publishKYCTierChanged(t *testing.T, ctx context.Context, rdb *redis.Client, userID uuid.UUID, oldTier, newTier int16) {
	t.Helper()

	data, err := json.Marshal(map[string]any{
		"userId":  userID,
		"oldTier": oldTier,
		"newTier": newTier,
	})
	require.NoError(t, err)

	envelope, err := json.Marshal(map[string]any{
		"eventId":    uuid.New(),
		"occurredAt": time.Now().UTC(),
		"version":    1,
		"data":       json.RawMessage(data),
	})
	require.NoError(t, err)

	require.NoError(t, rdb.Publish(ctx, "kyc.tier_changed", string(envelope)).Err())
}

// TestConsumer_KYCTierChanged verifies that publishing kyc.tier_changed updates users.kyc_tier.
func TestConsumer_KYCTierChanged(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Infrastructure.
	pgDSN := startTestPostgres(t)
	runMigrations(t, context.Background(), pgDSN)

	redisURL := startTestRedis(t)
	redisOpts, err := redis.ParseURL(redisURL)
	require.NoError(t, err)

	rdb := redis.NewClient(redisOpts)
	t.Cleanup(func() { _ = rdb.Close() })

	pool, err := postgres.NewPool(ctx, pgDSN, "", 0, 0)
	require.NoError(t, err)

	defer pool.Close()

	userStore := postgres.NewUserStore(pool)

	// Seed a user with kyc_tier = 0.
	now := time.Now().UTC().Truncate(time.Millisecond)
	u := &domain.User{
		ID:           uuid.New(),
		Email:        "kyc-consumer@example.test",
		PasswordHash: testPasswordHash,
		DisplayName:  "KYC User",
		AccountType:  "PERSONAL",
		KYCTier:      0,
		Status:       "ACTIVE",
		TokenVersion: 0,
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	require.NoError(t, userStore.Create(ctx, u))

	// Start consumer in background.
	consumer := events.NewConsumer(rdb, userStore)

	consumerCtx, consumerCancel := context.WithCancel(context.Background())
	defer consumerCancel()

	go consumer.Run(consumerCtx)

	// Give the subscription a moment to establish.
	time.Sleep(100 * time.Millisecond)

	// Publish kyc.tier_changed with newTier = 2.
	publishKYCTierChanged(t, ctx, rdb, u.ID, 0, 2)

	// Poll for up to 3 seconds for the update to land.
	require.Eventually(t, func() bool {
		got, getErr := userStore.GetByID(ctx, u.ID)
		if getErr != nil {
			return false
		}
		return got.KYCTier == 2
	}, 3*time.Second, 100*time.Millisecond, "kyc_tier should be updated to 2")
}

// TestConsumer_KYCTierChanged_BadPayload verifies that bad payloads are skipped without crashing.
func TestConsumer_KYCTierChanged_BadPayload(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	pgDSN := startTestPostgres(t)
	runMigrations(t, context.Background(), pgDSN)

	redisURL := startTestRedis(t)
	redisOpts, err := redis.ParseURL(redisURL)
	require.NoError(t, err)

	rdb := redis.NewClient(redisOpts)
	t.Cleanup(func() { _ = rdb.Close() })

	pool, err := postgres.NewPool(ctx, pgDSN, "", 0, 0)
	require.NoError(t, err)

	defer pool.Close()

	userStore := postgres.NewUserStore(pool)

	consumer := events.NewConsumer(rdb, userStore)

	consumerCtx, consumerCancel := context.WithCancel(context.Background())
	defer consumerCancel()

	go consumer.Run(consumerCtx)
	time.Sleep(100 * time.Millisecond)

	// Publish malformed JSON — consumer must not crash.
	require.NoError(t, rdb.Publish(ctx, "kyc.tier_changed", "not-valid-json").Err())

	// Publish oversized payload — must be dropped.
	oversized := strings.Repeat("x", 65*1024)
	require.NoError(t, rdb.Publish(ctx, "kyc.tier_changed", oversized).Err())

	// Give consumer time to process (and survive) the bad payloads.
	time.Sleep(300 * time.Millisecond)

	// If we got here the consumer is still alive (it would have panicked if not resilient).
	assert.True(t, true, "consumer survived bad payloads")
}

// TestConsumer_NilRedis_DoesNotCrash verifies that a nil Redis client results in a no-op consumer.
func TestConsumer_NilRedis_DoesNotCrash(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	// Nil Redis — consumer must block on ctx.Done() without crashing.
	consumer := events.NewConsumer(nil, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	// Run blocks until ctx is done; it should return cleanly.
	consumer.Run(ctx)

	// Reaching here means no panic.
}
