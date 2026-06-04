package events_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"sort"
	"strconv"
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

// testHMACSecret is the shared event-authentication secret used across consumer tests.
const testHMACSecret = "this-is-a-32-byte-test-secret-xx" //nolint:gosec // G101: test fixture, not a real credential

// contractSignature recomputes the EVENT HMAC CONTRACT signature exactly as the
// kyc publisher must (and as the consumer verifies): lowercase hex of
// HMAC-SHA256(secret, eventId|occurredAt|version|userId|newTier).
func contractSignature(secret, eventID, occurredAt, version, userID, newTier string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	canonical := strings.Join([]string{eventID, occurredAt, version, userID, newTier}, "|")
	_, _ = mac.Write([]byte(canonical))

	return hex.EncodeToString(mac.Sum(nil))
}

// signedEnvelope builds a kyc.tier_changed envelope JSON. When sign is true it
// attaches a valid contract signature; when false the signature field is set to the
// provided forgedSig (use "" to simulate a missing signature).
func signedEnvelope(t *testing.T, userID uuid.UUID, oldTier, newTier int16, sign bool, forgedSig string) string {
	t.Helper()

	eventID := uuid.New()
	// Fix the occurredAt textual form so signing and the wire bytes agree exactly.
	occurredAt := time.Now().UTC().Format(time.RFC3339Nano)
	const version = "1"

	sig := forgedSig
	if sign {
		sig = contractSignature(
			testHMACSecret,
			eventID.String(),
			occurredAt,
			version,
			userID.String(),
			strconv.FormatInt(int64(newTier), 10),
		)
	}

	data, err := json.Marshal(map[string]any{
		"userId":  userID,
		"oldTier": oldTier,
		"newTier": newTier,
	})
	require.NoError(t, err)

	envelope, err := json.Marshal(map[string]any{
		"eventId":    eventID,
		"occurredAt": occurredAt,
		"version":    1,
		"data":       json.RawMessage(data),
		"signature":  sig,
	})
	require.NoError(t, err)

	return string(envelope)
}

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

// publishKYCTierChanged publishes a correctly-signed kyc.tier_changed event to Redis.
func publishKYCTierChanged(t *testing.T, ctx context.Context, rdb *redis.Client, userID uuid.UUID, oldTier, newTier int16) {
	t.Helper()

	envelope := signedEnvelope(t, userID, oldTier, newTier, true, "")
	require.NoError(t, rdb.Publish(ctx, "kyc.tier_changed", envelope).Err())
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
	consumer := events.NewConsumer(rdb, userStore, testHMACSecret)

	consumerCtx, consumerCancel := context.WithCancel(context.Background())
	defer consumerCancel()

	go consumer.Run(consumerCtx)

	// Give the subscription a moment to establish.
	time.Sleep(100 * time.Millisecond)

	// Publish a correctly-signed kyc.tier_changed with newTier = 2.
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

// seedTestUser inserts an ACTIVE user with kyc_tier=0 and returns it.
func seedTestUser(t *testing.T, ctx context.Context, userStore *postgres.UserStore, email string) *domain.User {
	t.Helper()

	now := time.Now().UTC().Truncate(time.Millisecond)
	u := &domain.User{
		ID:           uuid.New(),
		Email:        email,
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

	return u
}

// startConsumerStack spins up Postgres + Redis containers, applies migrations, starts
// the consumer authenticated with testHMACSecret, and returns the connected Redis
// client and store. All tests in this file use the same shared test secret.
func startConsumerStack(t *testing.T) (*redis.Client, *postgres.UserStore) {
	t.Helper()

	ctx := context.Background()

	pgDSN := startTestPostgres(t)
	runMigrations(t, ctx, pgDSN)

	redisURL := startTestRedis(t)
	redisOpts, err := redis.ParseURL(redisURL)
	require.NoError(t, err)

	rdb := redis.NewClient(redisOpts)
	t.Cleanup(func() { _ = rdb.Close() })

	pool, err := postgres.NewPool(ctx, pgDSN, "", 0, 0)
	require.NoError(t, err)
	t.Cleanup(pool.Close)

	userStore := postgres.NewUserStore(pool)

	consumer := events.NewConsumer(rdb, userStore, testHMACSecret)

	consumerCtx, consumerCancel := context.WithCancel(context.Background())
	t.Cleanup(consumerCancel)

	go consumer.Run(consumerCtx)
	time.Sleep(100 * time.Millisecond)

	return rdb, userStore
}

// TestConsumer_KYCTierChanged_BadPayload verifies that bad payloads are skipped
// without crashing the loop AND without mutating any user's tier.
func TestConsumer_KYCTierChanged_BadPayload(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ctx := context.Background()
	rdb, userStore := startConsumerStack(t)

	u := seedTestUser(t, ctx, userStore, "badpayload@example.test")

	// Publish malformed JSON — consumer must not crash.
	require.NoError(t, rdb.Publish(ctx, "kyc.tier_changed", "not-valid-json").Err())

	// Publish oversized payload — must be dropped.
	oversized := strings.Repeat("x", 65*1024)
	require.NoError(t, rdb.Publish(ctx, "kyc.tier_changed", oversized).Err())

	// Give consumer time to process (and survive) the bad payloads.
	time.Sleep(300 * time.Millisecond)

	// Consumer survived AND applied nothing: the seeded user's tier is still 0.
	got, err := userStore.GetByID(ctx, u.ID)
	require.NoError(t, err)
	assert.Equal(t, int16(0), got.KYCTier, "bad payloads must not change kyc_tier")
}

// TestConsumer_ForgedSignature_Rejected is the decisive P0 test: an event with an
// INVALID HMAC signature MUST be dropped — the user's tier must NOT change. Without
// message authentication a forged Redis publish could elevate any user to Tier2.
func TestConsumer_ForgedSignature_Rejected(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ctx := context.Background()
	rdb, userStore := startConsumerStack(t)

	u := seedTestUser(t, ctx, userStore, "forged@example.test")

	// Forged signature: attacker tries to elevate to Tier2 with a bogus signature.
	forged := signedEnvelope(t, u.ID, 0, 2, false, "deadbeefdeadbeefdeadbeefdeadbeef")
	require.NoError(t, rdb.Publish(ctx, "kyc.tier_changed", forged).Err())

	// Wait, then assert the tier was NOT changed (event dropped).
	time.Sleep(500 * time.Millisecond)
	got, err := userStore.GetByID(ctx, u.ID)
	require.NoError(t, err)
	assert.Equal(t, int16(0), got.KYCTier, "forged-signature event must NOT change kyc_tier")
}

// TestConsumer_MissingSignature_Rejected verifies that an event with NO signature
// field is dropped (the tier is not applied).
func TestConsumer_MissingSignature_Rejected(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ctx := context.Background()
	rdb, userStore := startConsumerStack(t)

	u := seedTestUser(t, ctx, userStore, "nosig@example.test")

	// Empty signature ("") simulates a missing signature.
	unsigned := signedEnvelope(t, u.ID, 0, 2, false, "")
	require.NoError(t, rdb.Publish(ctx, "kyc.tier_changed", unsigned).Err())

	time.Sleep(500 * time.Millisecond)
	got, err := userStore.GetByID(ctx, u.ID)
	require.NoError(t, err)
	assert.Equal(t, int16(0), got.KYCTier, "missing-signature event must NOT change kyc_tier")
}

// TestConsumer_OutOfBoundsTier_Dropped verifies that events carrying a newTier
// outside [0, 3] are dropped without updating the DB (M2 bounds-check fix).
func TestConsumer_OutOfBoundsTier_Dropped(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ctx := context.Background()
	rdb, userStore := startConsumerStack(t)

	tests := []struct {
		name    string
		newTier int16
	}{
		{name: "negative tier", newTier: -1},
		{name: "tier above max", newTier: 4},
		{name: "very large tier", newTier: 100},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			u := seedTestUser(t, ctx, userStore, fmt.Sprintf("oob-%d@example.test", tc.newTier))

			// Build a correctly-signed envelope with the out-of-bounds tier.
			envelope := signedEnvelope(t, u.ID, 0, tc.newTier, true, "")
			require.NoError(t, rdb.Publish(ctx, "kyc.tier_changed", envelope).Err())

			// Give consumer time to receive and process.
			time.Sleep(500 * time.Millisecond)

			// Tier must remain 0 — the event should have been dropped.
			got, err := userStore.GetByID(ctx, u.ID)
			require.NoError(t, err)
			assert.Equal(t, int16(0), got.KYCTier, "out-of-bounds newTier must not be applied")
		})
	}
}

// NOTE: the valid-signature happy path (correctly-signed event IS applied) is covered
// by TestConsumer_KYCTierChanged above, which publishes via the now-signing
// publishKYCTierChanged helper and asserts kyc_tier becomes 2.

// TestConsumer_NilRedis_DoesNotCrash verifies that a nil Redis client results in a no-op consumer.
func TestConsumer_NilRedis_DoesNotCrash(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	// Nil Redis — consumer must block on ctx.Done() without crashing.
	consumer := events.NewConsumer(nil, nil, testHMACSecret)

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	// Run blocks until ctx is done; it should return cleanly.
	consumer.Run(ctx)

	// Reaching here means no panic.
}
