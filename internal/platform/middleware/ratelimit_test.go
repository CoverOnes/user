package middleware_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/CoverOnes/user/internal/platform/middleware"
	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	tcredis "github.com/testcontainers/testcontainers-go/modules/redis"
)

func init() {
	gin.SetMode(gin.TestMode)
}

// startTestRedis spins up a real Redis container via testcontainers and returns a
// connected client. The sliding-window limiter relies on Redis sorted-set + Lua
// semantics that cannot be faithfully mocked, so we exercise it against real Redis.
func startTestRedis(t *testing.T) *redis.Client {
	t.Helper()

	ctx := context.Background()

	ctr, err := tcredis.Run(ctx, "redis:7-alpine")
	require.NoError(t, err)

	t.Cleanup(func() {
		if termErr := ctr.Terminate(ctx); termErr != nil {
			t.Logf("terminate redis container: %v", termErr)
		}
	})

	url, err := ctr.ConnectionString(ctx)
	require.NoError(t, err)

	opts, err := redis.ParseURL(url)
	require.NoError(t, err)

	rdb := redis.NewClient(opts)
	t.Cleanup(func() { _ = rdb.Close() })

	require.NoError(t, rdb.Ping(ctx).Err())

	return rdb
}

// buildLimiterRouter wires a single guarded GET /ping endpoint behind the limiter
// so tests can drive it through the real Gin middleware path. A fixed client IP is
// forced so every request maps to the same limiter key regardless of the test host.
func buildLimiterRouter(rl *middleware.RateLimiter) *gin.Engine {
	r := gin.New()
	r.Use(func(c *gin.Context) {
		// Force a deterministic client IP so all requests share one limiter bucket.
		c.Request.RemoteAddr = "203.0.113.7:12345"
		c.Next()
	})
	r.Use(rl.Handler())
	r.GET("/ping", func(c *gin.Context) { c.Status(http.StatusOK) })

	return r
}

func doPing(t *testing.T, r http.Handler) int {
	t.Helper()

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/ping", http.NoBody)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	return w.Code
}

// TestRateLimiter_NilRedisPassThrough proves that with a nil Redis client the
// limiter degrades to the in-process fallback (token bucket, burst 10) rather than
// erroring — i.e. the nil-Redis pass-through contract is preserved after the
// sliding-window upgrade.
func TestRateLimiter_NilRedisPassThrough(t *testing.T) {
	t.Parallel()

	// limit is irrelevant on the nil path — the in-process fallback governs.
	rl := middleware.NewIPRateLimiter(nil, 5, time.Minute)
	r := buildLimiterRouter(rl)

	// The fallback burst is 10; the first 10 requests within a second must pass.
	for i := 0; i < 10; i++ {
		assert.Equal(t, http.StatusOK, doPing(t, r), "fallback request %d should pass", i+1)
	}
}

// TestRateLimiter_SlidingWindow_BasicLimit verifies the core admit/deny contract
// against real Redis: exactly `limit` requests succeed within a window, the next is
// rejected with 429, and after the window fully elapses requests are admitted again.
func TestRateLimiter_SlidingWindow_BasicLimit(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping Redis integration test in short mode")
	}

	const (
		limit  = 3
		window = 1 * time.Second
	)

	rdb := startTestRedis(t)
	rl := middleware.NewIPRateLimiter(rdb, limit, window)
	r := buildLimiterRouter(rl)

	// First `limit` requests pass.
	for i := 0; i < limit; i++ {
		require.Equal(t, http.StatusOK, doPing(t, r), "request %d within limit should pass", i+1)
	}

	// The (limit+1)-th request inside the same window is rejected.
	require.Equal(t, http.StatusTooManyRequests, doPing(t, r), "request over limit must be 429")

	// Wait for the rolling window to fully elapse, then requests are admitted again.
	time.Sleep(window + 200*time.Millisecond)
	assert.Equal(t, http.StatusOK, doPing(t, r), "after window elapses, request should pass again")
}

// TestEmailLoginLimiter_NilRedisFailsOpen proves the per-email login limiter allows
// every attempt when Redis is not configured (dev mode) — it must never lock users
// out because the backing store is absent.
func TestEmailLoginLimiter_NilRedisFailsOpen(t *testing.T) {
	t.Parallel()

	lim := middleware.NewEmailLoginLimiter(nil, 3, time.Minute)
	for i := 0; i < 10; i++ {
		assert.True(t, lim.Allow(context.Background(), "user@example.com"),
			"nil-Redis limiter must allow attempt %d", i+1)
	}
}

// TestEmailLoginLimiter_PerEmailLimit verifies that exactly `limit` attempts per
// normalized email are admitted within the window and the next is denied, while a
// DIFFERENT email is throttled independently (keys are per-email).
func TestEmailLoginLimiter_PerEmailLimit(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping Redis integration test in short mode")
	}

	const (
		limit  = 3
		window = 2 * time.Second
	)

	rdb := startTestRedis(t)
	lim := middleware.NewEmailLoginLimiter(rdb, limit, window)
	ctx := context.Background()

	// First `limit` attempts for victim@example.com pass; the next is denied.
	for i := 0; i < limit; i++ {
		require.True(t, lim.Allow(ctx, "victim@example.com"), "attempt %d within limit should pass", i+1)
	}
	require.False(t, lim.Allow(ctx, "victim@example.com"), "attempt over limit must be denied")

	// A different email is unaffected (independent key).
	assert.True(t, lim.Allow(ctx, "other@example.com"), "a different email must have its own budget")

	// After the window elapses the victim email is admitted again.
	time.Sleep(window + 200*time.Millisecond)
	assert.True(t, lim.Allow(ctx, "victim@example.com"), "after the window elapses, attempts should pass again")
}

// TestRateLimiter_SlidingWindow_BoundaryBurst is the decisive test that the fixed
// window has been replaced by a true sliding window.
//
// Under a FIXED window of length W, an attacker can issue `limit` requests at the
// tail of window N and `limit` more at the head of window N+1 — 2×limit requests
// within a span far shorter than W. A sliding window MUST reject the second burst
// because those earlier requests are still inside the rolling window.
//
// Strategy with W = 2s, limit = 3:
//  1. t≈0.0s  fire `limit` requests → all pass, window now holds 3 entries.
//  2. t≈1.1s  (past the midpoint, where a 1s-aligned fixed window would have reset
//     at least once) fire one more request. With a sliding window the three
//     original entries are still < 2s old, so the window is saturated and this
//     request MUST be rejected. A fixed-window implementation aligned to wall-clock
//     seconds would (at least intermittently) have reset and wrongly admit it.
//  3. t≈2.2s  the original three entries have aged out (>2s); a request now passes,
//     confirming the window genuinely slid rather than being stuck.
func TestRateLimiter_SlidingWindow_BoundaryBurst(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping Redis integration test in short mode")
	}

	const (
		limit  = 3
		window = 2 * time.Second
	)

	rdb := startTestRedis(t)
	rl := middleware.NewIPRateLimiter(rdb, limit, window)
	r := buildLimiterRouter(rl)

	start := time.Now()

	// Burst 1: saturate the window at t≈0.
	for i := 0; i < limit; i++ {
		require.Equal(t, http.StatusOK, doPing(t, r), "burst-1 request %d should pass", i+1)
	}

	// Advance ~1.1s — more than half the window, and past where a 1s-aligned fixed
	// window boundary would have rolled over. The original 3 entries are still in
	// the rolling window (age ≈1.1s < 2s), so this MUST be rejected.
	time.Sleep(1100 * time.Millisecond)
	require.Equal(t, http.StatusTooManyRequests, doPing(t, r),
		"sliding window must still reject within window despite crossing a fixed-window boundary")

	// Sanity-check timing: we are still inside the original window.
	require.Less(t, time.Since(start), window, "test precondition: still inside the original window")

	// Advance until the original entries have fully aged out of the 2s window.
	time.Sleep(window) // total elapsed now ≈ 2s + 1.1s ≫ window since the first burst
	assert.Equal(t, http.StatusOK, doPing(t, r),
		"after the original burst ages out, a fresh request should pass")
}
