// Package handler wires up Gin routes for the user service.
package handler

import (
	"log/slog"
	"time"

	"github.com/CoverOnes/user/internal/auth/jwt"
	"github.com/CoverOnes/user/internal/platform/health"
	"github.com/CoverOnes/user/internal/platform/middleware"
	"github.com/CoverOnes/user/internal/service"
	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
)

// RouterConfig holds all handler-level dependencies.
type RouterConfig struct {
	Auth    *service.AuthService
	Profile *service.ProfileService
	MFA     *service.MFAService
	Signer  *jwt.Signer
	Pool    *pgxpool.Pool
	Redis   *redis.Client // may be nil in dev

	// GatewayHMACSecret is the §24.1 shared secret used to verify the
	// gateway-origin identity signature. Empty == dev posture (verification
	// disabled); config validation guarantees it is non-empty in non-dev.
	GatewayHMACSecret string
}

// NewRouter builds and returns the configured Gin engine.
func NewRouter(cfg RouterConfig) *gin.Engine {
	gin.SetMode(gin.ReleaseMode)

	r := gin.New()
	r.SetTrustedProxies(nil) //nolint:errcheck // nil proxy list disables proxy trust; gin docs confirm error is always nil for nil argument

	// Global middleware chain (order per CONVENTIONS.md).
	r.Use(middleware.Recover())
	r.Use(middleware.RequestID())
	r.Use(middleware.SecurityHeaders())
	r.Use(accessLogger())

	// Health endpoints — registered BEFORE the rate limiter so that liveness /
	// readiness probes are never rate-limited (m1/router fix: middleware ordering).
	h := health.NewHandler(cfg.Pool)
	r.GET("/healthz", h.Liveness)
	r.GET("/readyz", h.Readiness)

	// JWKS — public, cache-friendly; no rate limit needed (key material is public).
	jwksH := NewJWKSHandler(cfg.Signer)
	r.GET("/jwks", jwksH.Get)

	// Rate limiter — 60 req/min per IP applied to all routes registered below.
	ipRL := middleware.NewIPRateLimiter(cfg.Redis, 60, time.Minute)
	r.Use(ipRL.Handler())

	// Auth routes — public, but with no-cache + tighter rate limit.
	authRL := middleware.NewAccountRateLimiter(cfg.Redis, 20, time.Minute)
	authH := NewAuthHandler(cfg.Auth, cfg.Signer)

	authGroup := r.Group("/v1/auth")
	authGroup.Use(middleware.NoCache())
	authGroup.Use(authRL.Handler())
	authGroup.POST("/register", authH.Register)
	authGroup.POST("/login", authH.Login)
	authGroup.POST("/refresh", authH.Refresh)
	authGroup.POST("/verify-email", authH.VerifyEmail)
	authGroup.POST("/resend-verification", authH.ResendVerification)
	// Logout requires access token.
	authGroup.POST("/logout", middleware.Auth(cfg.Signer), authH.Logout)

	// Protected routes — require valid access token, Tier >= 0.
	authMW := middleware.Auth(cfg.Signer)
	me := r.Group("/v1/me")
	// Defense-in-depth (§24.1): verify the gateway-origin HMAC signature BEFORE
	// the JWT auth middleware trusts any request on this protected group. When the
	// secret is empty (dev) this is a no-op passthrough, matching the gateway's
	// dev signing-skip.
	me.Use(middleware.VerifyGatewaySignature(cfg.GatewayHMACSecret))
	me.Use(authMW)
	meH := NewMeHandler(cfg.Profile)
	me.GET("", meH.Get)
	profH := NewProfileHandler(cfg.Profile)
	me.GET("/profile", profH.Get)
	// PUT /profile requires Tier >= 1.
	me.PUT("/profile", middleware.RequireTier(1), profH.Update)
	// Session management.
	sessH := NewSessionHandler(cfg.Auth)
	me.POST("/sessions/revoke-all", sessH.RevokeAll)

	// TOTP 2FA primitives (Increment 3). Protected by the same Auth middleware as
	// the rest of /v1/me. NOT wired into login this wave — enroll/confirm/verify/
	// disable only manage the user's own MFA state. Registered only when the MFA
	// service is wired (it always is in main.go; the nil-guard keeps tests that build
	// a minimal router from panicking).
	if cfg.MFA != nil {
		mfaH := NewMFAHandler(cfg.MFA)
		totp := me.Group("/mfa/totp")

		// Per-authenticated-user (JWT subject) brute-force limiter on the CODE endpoints
		// (confirm / verify / disable). Budget 5 attempts/min/user keyed rl:mfa:<subject>.
		// It FAILS CLOSED on a Redis outage — unlike the login limiter (which fails open
		// for availability), an unbounded TOTP-code-guessing window is a brute-force
		// oracle (CWE-307), so a Redis error must DENY rather than open it. Enroll is
		// deliberately NOT limited here: it takes no code, so it is not a guessing surface.
		mfaCodeRL := middleware.NewMFACodeLimiter(cfg.Redis, 5, time.Minute)

		totp.POST("/enroll", mfaH.Enroll)
		totp.POST("/confirm", mfaCodeRL.Handler(), mfaH.Confirm)
		totp.POST("/verify", mfaCodeRL.Handler(), mfaH.Verify)
		totp.POST("/disable", mfaCodeRL.Handler(), mfaH.Disable)
		// DELETE alias for disable (same {code}-verified semantics + same code limiter).
		totp.DELETE("", mfaCodeRL.Handler(), mfaH.Disable)
	}

	return r
}

// accessLogger returns a minimal slog-based access-log middleware.
func accessLogger() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		c.Next()
		slog.Info(
			"http",
			"method", c.Request.Method,
			"path", c.Request.URL.Path,
			"status", c.Writer.Status(),
			"latency_ms", time.Since(start).Milliseconds(),
			"request_id", c.GetString("request_id"),
		)
	}
}
