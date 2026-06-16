// Package handler wires up Gin routes for the user service.
package handler

import (
	"log/slog"
	"time"

	"github.com/CoverOnes/user/internal/auth/jwt"
	"github.com/CoverOnes/user/internal/crypto/pii"
	"github.com/CoverOnes/user/internal/platform/health"
	"github.com/CoverOnes/user/internal/platform/middleware"
	"github.com/CoverOnes/user/internal/service"
	"github.com/CoverOnes/user/internal/store"
	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
)

// RouterConfig holds all handler-level dependencies.
type RouterConfig struct {
	Auth    *service.AuthService
	Profile *service.ProfileService
	MFA     *service.MFAService
	OAuth   *service.OAuthService // may be nil when OAuth is not configured
	Signer  *jwt.Signer
	Pool    *pgxpool.Pool
	Redis   *redis.Client // may be nil in dev

	// GatewayHMACSecret is the §24.1 shared secret used to verify the
	// gateway-origin identity signature. Empty == dev posture (verification
	// disabled); config validation guarantees it is non-empty in non-dev.
	GatewayHMACSecret string

	// UserRateLimitPerMin is the sustained per-authenticated-user request rate
	// for the /v1/me group (tokens/minute). 0 disables the limiter entirely.
	// Source: config.UserRateLimitPerMin (USER_USER_RATE_LIMIT_PER_MIN).
	UserRateLimitPerMin int

	// UserRateLimitBurst is the maximum burst size for the per-user /v1/me limiter.
	// Source: config.UserRateLimitBurst (USER_USER_RATE_LIMIT_BURST).
	UserRateLimitBurst int

	// OAuthFrontendPostLoginURL is passed to OAuthHandler for callback redirects.
	// Required when OAuth != nil.
	OAuthFrontendPostLoginURL string

	// KycS2SToken is the bearer token the kyc service presents on the S2S
	// identity-match endpoint. When non-empty, POST /internal/v1/users/:userId/verify-identity-match
	// is registered. When empty, the endpoint is not registered.
	// Source: config.KycS2SToken (USER_KYC_S2S_TOKEN).
	KycS2SToken string

	// KycEncryptor is the PII encryptor used by the identity-match endpoint.
	// Must be non-nil when KycS2SToken is non-empty.
	KycEncryptor *pii.Encryptor

	// KycUserStore is the user store used by the identity-match endpoint.
	// Must be non-nil when KycS2SToken is non-empty.
	KycUserStore store.UserStore
}

// NewRouter builds and returns the configured Gin engine.
func NewRouter(cfg *RouterConfig) *gin.Engine {
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
	authGroup.POST("/forgot-password", authH.ForgotPassword)
	authGroup.POST("/reset-password", authH.ResetPassword)
	// Logout requires access token.
	authGroup.POST("/logout", middleware.Auth(cfg.Signer), authH.Logout)

	// OAuth social login routes (Increment 4).
	// GET /v1/auth/oauth/:provider/start — public, returns authorization URL.
	// GET /v1/auth/oauth/:provider/callback — public, browser redirect target.
	// POST /v1/auth/oauth/exchange — public, consumes one-time code → token pair.
	// Only registered when the OAuthService is wired (non-nil).
	if cfg.OAuth != nil {
		oauthH := NewOAuthHandler(cfg.OAuth, cfg.OAuthFrontendPostLoginURL)
		// Start + callback share authRL (they're in the public auth surface).
		authGroup.GET("/oauth/:provider/start", oauthH.Start)
		authGroup.GET("/oauth/:provider/callback", oauthH.Callback)
		// Exchange is intentionally outside the authGroup rate limiter because
		// the one-time code is single-use and short-lived — it is already the
		// rate-limiting artifact. The IP-level ipRL still applies.
		r.POST("/v1/auth/oauth/exchange", middleware.NoCache(), oauthH.Exchange)
		// Register completes the no-email provider flow (LINE without email scope).
		// The regToken is single-use + short-lived (15 min) so it acts as its own
		// rate-limiting artifact. IP-level ipRL still applies.
		r.POST("/v1/auth/oauth/register", middleware.NoCache(), oauthH.Register)
	}

	// Protected routes — require valid access token, Tier >= 0.
	//
	// /v1/auth vs /v1/me identity-source split (security note):
	//   /v1/auth (login/register/reset) is PRE-authentication: no verified user_id
	//   exists yet, so a per-user limiter would no-op. Those routes are guarded by
	//   IP-level (ipRL) and account-level (authRL) limiters above.
	//   /v1/me is POST-authentication: the JWT subject in the verified token is a
	//   stable, gateway-verified user identity that cannot be spoofed by a client.
	//   The per-user limiter is therefore mounted here — AFTER VerifyGatewaySignature
	//   and Auth — so the key is always attacker-proof.
	authMW := middleware.Auth(cfg.Signer)
	me := r.Group("/v1/me")
	// Defense-in-depth (§24.1): verify the gateway-origin HMAC signature BEFORE
	// the JWT auth middleware trusts any request on this protected group. When the
	// secret is empty (dev) this is a no-op passthrough, matching the gateway's
	// dev signing-skip.
	me.Use(middleware.VerifyGatewaySignature(cfg.GatewayHMACSecret, cfg.Redis))
	me.Use(authMW)
	// Per-authenticated-user token-bucket limiter — mounted AFTER VerifyGatewaySignature
	// + Auth so the JWT subject (the limiter key) is always a gateway-verified identity,
	// never attacker-supplied. When UserRateLimitPerMin == 0 the limiter is disabled
	// (no-op), e.g. in environments that rate-limit at the gateway layer instead.
	if cfg.UserRateLimitPerMin > 0 {
		userRL := middleware.NewGeneralUserRateLimiter(cfg.UserRateLimitPerMin, cfg.UserRateLimitBurst)
		me.Use(userRL.Handler())
	}
	meH := NewMeHandler(cfg.Profile)
	me.GET("", meH.Get)
	profH := NewProfileHandler(cfg.Profile)
	me.GET("/profile", profH.Get)
	// PUT /profile requires Tier >= 1.
	me.PUT("/profile", middleware.RequireTier(1), profH.Update)
	// Session management.
	sessH := NewSessionHandler(cfg.Auth)
	me.POST("/sessions/revoke-all", sessH.RevokeAll)

	// OAuth identity bind/unbind (Increment 4) — protected, same Auth chain as /v1/me.
	// POST  /v1/me/identities/:provider — start bind flow (returns authorize URL).
	// DELETE /v1/me/identities/:provider — unbind (guarded: last-method check).
	if cfg.OAuth != nil {
		oauthH := NewOAuthHandler(cfg.OAuth, cfg.OAuthFrontendPostLoginURL)
		identities := me.Group("/identities")
		// GET /v1/me/identities — list bound OAuth identities + hasPassword.
		identities.GET("", oauthH.ListIdentities)
		identities.POST("/:provider", oauthH.BindStart)
		identities.DELETE("/:provider", oauthH.Unbind)
	}

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

	// Internal S2S identity-match endpoint for the kyc service.
	// Registered only when USER_KYC_S2S_TOKEN is set; otherwise the endpoint returns 404.
	if cfg.KycS2SToken != "" {
		matchH := NewIdentityMatchHandler(cfg.KycUserStore, cfg.KycEncryptor)
		internal := r.Group("/internal/v1/users")
		internal.Use(middleware.RequireServiceIdentity(cfg.KycS2SToken))
		// NoCache prevents any intermediate proxy / CDN from caching identity-match responses.
		// Identity match results are user-specific and must never be shared across callers.
		internal.Use(middleware.NoCache())
		internal.POST("/:userId/verify-identity-match", matchH.VerifyIdentityMatch)
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
