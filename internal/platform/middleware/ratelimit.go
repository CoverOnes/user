package middleware

import (
	"context"
	"crypto/rand"
	"encoding/hex"
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

// slidingWindowScript implements a sliding-window rate limiter over a Redis
// sorted set, evaluated atomically server-side.
//
// KEYS[1] = the per-caller sorted-set key
// ARGV[1] = now            (unix-nanoseconds, the score of this request)
// ARGV[2] = windowStart    (now - window, in unix-nanoseconds)
// ARGV[3] = limit          (max requests permitted within the window)
// ARGV[4] = windowNanos    (window length in nanoseconds, used for the key TTL)
// ARGV[5] = member         (unique member id for this request)
//
// Semantics:
//  1. ZREMRANGEBYSCORE evicts entries older than windowStart, so the set only
//     ever holds requests inside the rolling window (unlike a fixed window, the
//     boundary slides with every call — a paced burst across a calendar boundary
//     can no longer double the effective rate).
//  2. ZCARD counts the surviving in-window requests.
//  3. If the count is already at/above the limit, return -1 WITHOUT adding the
//     current request (so a rejected request neither extends the window nor is
//     itself counted). The -1 sentinel is unambiguous: the Go caller treats any
//     negative return as "denied".
//  4. Otherwise ZADD this request and return the new (admitted) count.
//
// PEXPIRE bounds the key lifetime to one window past the last write, so idle
// keys self-evict and memory stays O(active callers × limit).
const slidingWindowScript = `
local key = KEYS[1]
local now = tonumber(ARGV[1])
local windowStart = tonumber(ARGV[2])
local limit = tonumber(ARGV[3])
local windowNanos = tonumber(ARGV[4])
local member = ARGV[5]

redis.call('ZREMRANGEBYSCORE', key, '-inf', windowStart)
local count = redis.call('ZCARD', key)

if count >= limit then
  redis.call('PEXPIRE', key, math.ceil(windowNanos / 1000000))
  return -1
end

redis.call('ZADD', key, now, member)
redis.call('PEXPIRE', key, math.ceil(windowNanos / 1000000))
return count + 1
`

// RateLimiter is a Redis-backed sliding-window rate limiter with an in-process
// token-bucket fallback that engages when Redis errors (F4 — fails SAFE, not open).
//
// The sliding window is implemented with a per-caller Redis sorted set: each
// request is a member scored by its arrival time, stale members outside the
// rolling window are trimmed on every call, and the surviving cardinality is the
// request count. This removes the fixed-window boundary-burst weakness where a
// caller could issue `limit` requests at the tail of one window and `limit` more
// at the head of the next — 2× the intended rate over a few milliseconds.
type RateLimiter struct {
	rdb      *redis.Client
	script   *redis.Script
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
		script: redis.NewScript(slidingWindowScript),
		limit:  limit,
		window: window,
		keyFunc: func(c *gin.Context) string {
			return fmt.Sprintf("rl:ip:%s", c.ClientIP())
		},
		fallback: newFallbackLimiter(r, fallbackBurst),
	}
}

// EmailLoginLimiter applies a per-normalized-email sliding-window rate limit for
// login attempts (credential-stuffing defense). Unlike the IP-keyed middleware
// limiter it is invoked from the service layer once the email has been parsed, so
// an attacker spraying one email across many IPs is still throttled.
//
// It FAILS SAFE: when Redis is unavailable or errors, Allow returns true so a Redis
// outage cannot lock every account out of login (availability > strict throttling
// for this control; the IP limiter and password check remain in force).
type EmailLoginLimiter struct {
	rdb       *redis.Client
	script    *redis.Script
	limit     int
	window    time.Duration
	keyPrefix string
}

// NewEmailLoginLimiter builds a per-email login limiter. A nil rdb disables the
// control (Allow always returns true) — same dev-mode contract as the middleware.
func NewEmailLoginLimiter(rdb *redis.Client, limit int, window time.Duration) *EmailLoginLimiter {
	return &EmailLoginLimiter{
		rdb:       rdb,
		script:    redis.NewScript(slidingWindowScript),
		limit:     limit,
		window:    window,
		keyPrefix: "rl:login:email:",
	}
}

// NewEmailVerificationLimiter builds a per-email limiter for the resend-verification
// endpoint (default 3/hour — set by the caller). It mirrors NewEmailLoginLimiter but
// uses a distinct Redis key namespace so resend throttling and login throttling are
// independent. A nil rdb disables the control (Allow always returns true) — same
// dev-mode contract.
func NewEmailVerificationLimiter(rdb *redis.Client, limit int, window time.Duration) *EmailLoginLimiter {
	return &EmailLoginLimiter{
		rdb:       rdb,
		script:    redis.NewScript(slidingWindowScript),
		limit:     limit,
		window:    window,
		keyPrefix: "rl:resend:email:",
	}
}

// Allow reports whether an attempt for the given normalized email is admitted.
// On a nil Redis client or any Redis error it returns true (fail-safe).
func (l *EmailLoginLimiter) Allow(ctx context.Context, normalizedEmail string) bool {
	if l.rdb == nil {
		return true
	}

	now := time.Now().UnixNano()
	windowStart := now - l.window.Nanoseconds()
	member := fmt.Sprintf("%d-%s", now, randMember())
	key := l.keyPrefix + normalizedEmail

	res, err := l.script.Run(
		ctx,
		l.rdb,
		[]string{key},
		now,
		windowStart,
		l.limit,
		l.window.Nanoseconds(),
		member,
	).Int64()
	if err != nil {
		// Fail safe: a Redis outage must not lock users out.
		slog.Warn("email limiter redis error; failing open for availability", "err", err, "keyPrefix", l.keyPrefix)

		return true
	}

	return res >= 0
}

// NewAccountRateLimiter builds a limiter keyed by email (for login attempts).
func NewAccountRateLimiter(rdb *redis.Client, limit int, window time.Duration) *RateLimiter {
	r := rate.Limit(float64(limit) / window.Seconds())

	return &RateLimiter{
		rdb:    rdb,
		script: redis.NewScript(slidingWindowScript),
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

		allowed, err := rl.allowSlidingWindow(ctx, key)
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

		if !allowed {
			c.Abort()
			httpx.ErrCode(c, http.StatusTooManyRequests, "RATE_LIMITED", "too many requests, please try again later")
			return
		}

		c.Next()
	}
}

// allowSlidingWindow evaluates the sliding-window Lua script atomically on Redis
// and reports whether the current request is admitted. A negative script result
// (the -1 sentinel) means the rolling window is already saturated.
func (rl *RateLimiter) allowSlidingWindow(ctx context.Context, key string) (bool, error) {
	now := time.Now().UnixNano()
	windowStart := now - rl.window.Nanoseconds()

	// A unique member per request: nanosecond timestamp + a random suffix so two
	// requests arriving in the same nanosecond do not collide on the same ZSET member
	// (a collision would silently undercount). crypto/rand keeps it non-guessable.
	member := fmt.Sprintf("%d-%s", now, randMember())

	res, err := rl.script.Run(
		ctx,
		rl.rdb,
		[]string{key},
		now,
		windowStart,
		rl.limit,
		rl.window.Nanoseconds(),
		member,
	).Int64()
	if err != nil {
		return false, err
	}

	return res >= 0, nil
}

// randMember returns a short hex string from a crypto-random source, used only to
// disambiguate sorted-set members that share a timestamp. On the (practically
// impossible) read error it falls back to a fixed suffix — correctness is not
// security-critical here, only collision-avoidance.
func randMember() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "x"
	}

	return hex.EncodeToString(b[:])
}
