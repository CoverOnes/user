package middleware

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/CoverOnes/user/internal/platform/httpx"
	"github.com/gin-gonic/gin"
	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/redis/go-redis/v9"
	"golang.org/x/time/rate"
)

// fallbackBurst is the token-bucket burst for the in-process fallback limiter.
// Set conservatively: 10 requests per second per IP.
const fallbackBurst = 10

// fallbackLRUCap is the maximum number of unique keys tracked by the in-process
// fallback limiter. When the cap is reached, the least-recently-used entry is
// evicted, bounding memory to O(cap × sizeof(*rate.Limiter)) regardless of how
// many unique source IPs an attacker rotates through (C2 — memory-DoS fix).
const fallbackLRUCap = 100_000

// RateLimiter is a Redis-backed fixed-window rate limiter with an in-process
// token-bucket fallback that engages when Redis errors (F4 — fails SAFE, not open).
// Note: the fixed-window vs sliding-window precision upgrade is a deferred follow-up.
type RateLimiter struct {
	rdb      *redis.Client
	limit    int
	window   time.Duration
	keyFunc  func(c *gin.Context) string
	fallback *fallbackLimiter
}

// fallbackLimiter holds per-IP token buckets for the in-process safety net.
// The bucket map is bounded by an LRU cache (cap = fallbackLRUCap) so that an
// attacker rotating source IPs cannot exhaust server memory.
type fallbackLimiter struct {
	mu      sync.Mutex
	buckets *lru.Cache[string, *rate.Limiter]
	r       rate.Limit
	burst   int
}

func newFallbackLimiter(r rate.Limit, burst int) *fallbackLimiter {
	cache, err := lru.New[string, *rate.Limiter](fallbackLRUCap)
	if err != nil {
		// lru.New only errors when cap <= 0, which cannot happen here.
		panic(fmt.Sprintf("fallbackLimiter: unexpected lru.New error: %v", err))
	}

	return &fallbackLimiter{
		buckets: cache,
		r:       r,
		burst:   burst,
	}
}

func (f *fallbackLimiter) allow(key string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()

	lim, ok := f.buckets.Get(key)
	if !ok {
		lim = rate.NewLimiter(f.r, f.burst)
		f.buckets.Add(key, lim)
	}

	return lim.Allow()
}

// NewIPRateLimiter builds a limiter keyed by client IP.
func NewIPRateLimiter(rdb *redis.Client, limit int, window time.Duration) *RateLimiter {
	r := rate.Limit(float64(limit) / window.Seconds())

	return &RateLimiter{
		rdb:    rdb,
		limit:  limit,
		window: window,
		keyFunc: func(c *gin.Context) string {
			return fmt.Sprintf("rl:ip:%s", c.ClientIP())
		},
		fallback: newFallbackLimiter(r, fallbackBurst),
	}
}

// NewAccountRateLimiter builds a limiter keyed by email (for login attempts).
func NewAccountRateLimiter(rdb *redis.Client, limit int, window time.Duration) *RateLimiter {
	r := rate.Limit(float64(limit) / window.Seconds())

	return &RateLimiter{
		rdb:    rdb,
		limit:  limit,
		window: window,
		keyFunc: func(c *gin.Context) string {
			// The email is not yet parsed here; use IP as fallback at middleware level.
			// Fine-grained per-account limiting happens in the service layer.
			return fmt.Sprintf("rl:login:ip:%s", c.ClientIP())
		},
		fallback: newFallbackLimiter(r, fallbackBurst),
	}
}

// Handler returns the Gin middleware function.
func (rl *RateLimiter) Handler() gin.HandlerFunc {
	return func(c *gin.Context) {
		if rl.rdb == nil {
			// Redis not configured (dev mode) — apply in-process fallback limiter so
			// the service still has brute-force protection even without Redis (F4).
			key := rl.keyFunc(c)
			if !rl.fallback.allow(key) {
				c.Abort()
				httpx.ErrCode(c, http.StatusTooManyRequests, "RATE_LIMITED", "too many requests, please try again later")
				return
			}

			c.Next()
			return
		}

		key := rl.keyFunc(c)
		ctx := c.Request.Context()

		count, err := rl.increment(ctx, key)
		if err != nil {
			// Redis error — engage the in-process fallback limiter instead of failing open (F4).
			slog.Warn("rate limiter redis error; applying in-process fallback limiter", "err", err)
			if !rl.fallback.allow(key) {
				c.Abort()
				httpx.ErrCode(c, http.StatusTooManyRequests, "RATE_LIMITED", "too many requests, please try again later")
				return
			}

			c.Next()
			return
		}

		if count > rl.limit {
			c.Abort()
			httpx.ErrCode(c, http.StatusTooManyRequests, "RATE_LIMITED", "too many requests, please try again later")
			return
		}

		c.Next()
	}
}

func (rl *RateLimiter) increment(ctx context.Context, key string) (int, error) {
	pipe := rl.rdb.Pipeline()
	incr := pipe.Incr(ctx, key)
	// ExpireNX sets the TTL only when the key has no expiry yet (the first request
	// in a window). Plain Expire would reset the window on every request, letting a
	// paced attacker bypass the limit entirely (M-NEW-1 fixed-window correctness).
	pipe.ExpireNX(ctx, key, rl.window)

	_, err := pipe.Exec(ctx)
	if err != nil {
		return 0, err
	}

	return int(incr.Val()), nil
}
