package handler

import (
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"strings"

	"github.com/CoverOnes/user/internal/auth/jwt"
	"github.com/CoverOnes/user/internal/platform/httpx"
	"github.com/CoverOnes/user/internal/platform/middleware"
	"github.com/CoverOnes/user/internal/service"
	"github.com/gin-gonic/gin"
)

const maxBodyBytes = 1 << 20 // 1 MB

// secondsPerHour converts the refresh-token TTL (configured in hours) to the
// cookie MaxAge (seconds).
const secondsPerHour = 3600

// AuthHandler handles authentication endpoints.
type AuthHandler struct {
	auth   *service.AuthService
	signer *jwt.Signer
	// cookieDomain is the Domain attribute for the refresh-token cookie. Empty
	// string omits the attribute (dev: cookie scoped to request host).
	cookieDomain string
	// refreshTTLHours is the refresh-token TTL in hours; it drives the cookie
	// MaxAge (refreshTTLHours * 3600 seconds).
	refreshTTLHours int
}

// NewAuthHandler returns an AuthHandler. cookieDomain is the refresh-token cookie
// Domain attribute (empty in dev) and refreshTTLHours is the refresh-token TTL used
// to compute the cookie MaxAge.
func NewAuthHandler(auth *service.AuthService, signer *jwt.Signer, cookieDomain string, refreshTTLHours int) *AuthHandler {
	return &AuthHandler{
		auth:            auth,
		signer:          signer,
		cookieDomain:    cookieDomain,
		refreshTTLHours: refreshTTLHours,
	}
}

// RegisterRequest is the register endpoint request body.
type RegisterRequest struct {
	Email       string `json:"email" binding:"required,email,max=254"`
	Password    string `json:"password" binding:"required,min=12,max=128"`
	DisplayName string `json:"displayName" binding:"required,max=80"`
	AccountType string `json:"accountType" binding:"required"`
	// LegalName is the user's real name — required for BOTH account types.
	LegalName string `json:"legalName" binding:"required,max=100"`
	// NationalID — required + checksum-validated for PERSONAL at the service layer;
	// the binding only bounds length (max=10). Optional/ignored for COMPANY.
	NationalID  string `json:"nationalId" binding:"max=10"`
	CompanyName string `json:"companyName" binding:"max=200"`
}

// Register handles POST /v1/auth/register.
// Returns 201 with the user object only (no tokens — register issues no tokens).
func (h *AuthHandler) Register(c *gin.Context) {
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxBodyBytes)

	var req RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		httpx.ErrCode(c, http.StatusBadRequest, "VALIDATION_ERROR", err.Error())
		return
	}

	out, err := h.auth.Register(c.Request.Context(), service.RegisterInput{
		Email:       req.Email,
		Password:    req.Password,
		DisplayName: req.DisplayName,
		AccountType: strings.ToUpper(req.AccountType),
		LegalName:   req.LegalName,
		NationalID:  req.NationalID,
		CompanyName: req.CompanyName,
	})
	if err != nil {
		httpx.Err(c, err)
		return
	}

	u := out.User
	httpx.Created(c, gin.H{
		"user": gin.H{
			"id":            u.ID,
			"email":         u.Email,
			"displayName":   u.DisplayName,
			"accountType":   u.AccountType,
			"kycTier":       u.KYCTier,
			"status":        u.Status,
			"emailVerified": u.EmailVerified,
		},
	})
}

// VerifyEmailRequest is the verify-email endpoint request body.
type VerifyEmailRequest struct {
	Token string `json:"token" binding:"required,max=512"`
}

// VerifyEmail handles POST /v1/auth/verify-email.
// All failure modes return the single generic 400 INVALID_VERIFICATION_TOKEN.
func (h *AuthHandler) VerifyEmail(c *gin.Context) {
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxBodyBytes)

	var req VerifyEmailRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		httpx.ErrCode(c, http.StatusBadRequest, "VALIDATION_ERROR", err.Error())
		return
	}

	if err := h.auth.VerifyEmail(c.Request.Context(), req.Token); err != nil {
		httpx.Err(c, err)
		return
	}

	httpx.OK(c, gin.H{"emailVerified": true})
}

// ResendVerificationRequest is the resend-verification endpoint request body.
type ResendVerificationRequest struct {
	Email string `json:"email" binding:"required,email,max=254"`
}

// resendVerificationMessage is the constant, enumeration-safe response message.
const resendVerificationMessage = "If an account requires verification, an email has been sent."

// ResendVerification handles POST /v1/auth/resend-verification.
// ALWAYS returns 202 with a constant message regardless of account existence or
// state (no enumeration). The actual send (if any) happens in the service.
func (h *AuthHandler) ResendVerification(c *gin.Context) {
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxBodyBytes)

	var req ResendVerificationRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		httpx.ErrCode(c, http.StatusBadRequest, "VALIDATION_ERROR", err.Error())
		return
	}

	// Fire-and-forget at the response level: the service swallows all outcomes so
	// the response is identical whether or not anything was sent.
	h.auth.ResendVerification(c.Request.Context(), req.Email)

	httpx.Accepted(c, gin.H{"message": resendVerificationMessage})
}

// LoginRequest is the login endpoint request body.
type LoginRequest struct {
	Email             string  `json:"email" binding:"required,email"`
	Password          string  `json:"password" binding:"required"`
	DeviceFingerprint *string `json:"deviceFingerprint" binding:"omitempty,max=512"`
}

// Login handles POST /v1/auth/login.
func (h *AuthHandler) Login(c *gin.Context) {
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxBodyBytes)

	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		httpx.ErrCode(c, http.StatusBadRequest, "VALIDATION_ERROR", err.Error())
		return
	}

	ip, err := netip.ParseAddr(c.ClientIP())
	if err != nil {
		// Non-critical: proceed with zero addr.
		slog.Warn("could not parse client IP", "err", err)
	}

	ua := c.GetHeader("User-Agent")
	var uaPtr *string
	if ua != "" {
		truncated := ua
		if len(ua) > 512 {
			truncated = ua[:512]
		}

		uaPtr = &truncated
	}

	pair, err := h.auth.Login(c.Request.Context(), service.LoginInput{
		Email:             req.Email,
		Password:          req.Password,
		DeviceFingerprint: req.DeviceFingerprint,
		IPAddr:            ip,
		UserAgent:         uaPtr,
	})
	if err != nil {
		httpx.Err(c, err)
		return
	}

	// The refresh token is delivered as an HttpOnly cookie (never in the body) so
	// that JS / an XSS payload can never read it.
	setRefreshCookie(c, pair.RefreshToken, h.refreshTTLHours*secondsPerHour, h.cookieDomain)

	httpx.OK(c, gin.H{
		"accessToken": pair.AccessToken,
		"tokenType":   "Bearer",
		"expiresIn":   pair.ExpiresIn,
	})
}

// RefreshRequest is the token refresh endpoint request body. The refresh token is
// read from the HttpOnly cookie, NOT the body, so the body carries only the
// optional device fingerprint. The body itself is optional (empty body is valid).
type RefreshRequest struct {
	DeviceFingerprint *string `json:"deviceFingerprint" binding:"omitempty,max=512"`
}

// Refresh handles POST /v1/auth/refresh.
//
// The refresh token is read exclusively from the HttpOnly `refresh_token` cookie.
// A missing cookie yields 401 UNAUTHORIZED (never falls back to the body — the
// token never travels in the body anymore).
func (h *AuthHandler) Refresh(c *gin.Context) {
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxBodyBytes)

	// The body is optional (it carries only an optional deviceFingerprint). An empty
	// body is valid; only a malformed/oversized body is rejected. c.Cookie below is
	// the sole source of the refresh token.
	var req RefreshRequest
	if err := c.ShouldBindJSON(&req); err != nil && !errors.Is(err, io.EOF) {
		httpx.ErrCode(c, http.StatusBadRequest, "VALIDATION_ERROR", err.Error())
		return
	}

	token, err := c.Cookie(refreshCookieName)
	if err != nil || token == "" {
		// No refresh cookie present → not authenticated to refresh.
		httpx.ErrCode(c, http.StatusUnauthorized, "UNAUTHORIZED", "refresh token cookie missing")
		return
	}

	// token_version enforcement is now server-side: the service compares the version
	// stored in the refresh_tokens row against the fresh users.token_version from DB.
	// The handler does not extract or forward any version from the client (M1 fix).
	ip, _ := netip.ParseAddr(c.ClientIP()) // non-critical: zero addr used on parse error; ClientIP() always returns a valid address or loopback

	ua := c.GetHeader("User-Agent")
	var uaPtr *string
	if ua != "" {
		truncated := ua
		if len(ua) > 512 {
			truncated = ua[:512]
		}

		uaPtr = &truncated
	}

	pair, err := h.auth.Refresh(c.Request.Context(), service.RefreshInput{
		RawToken:          token,
		DeviceFingerprint: req.DeviceFingerprint,
		IPAddr:            ip,
		UserAgent:         uaPtr,
	})
	if err != nil {
		httpx.Err(c, err)
		return
	}

	// Rotate the cookie to the newly-issued refresh token.
	setRefreshCookie(c, pair.RefreshToken, h.refreshTTLHours*secondsPerHour, h.cookieDomain)

	httpx.OK(c, gin.H{
		"accessToken": pair.AccessToken,
		"tokenType":   "Bearer",
		"expiresIn":   pair.ExpiresIn,
	})
}

// Logout handles POST /v1/auth/logout.
//
// The refresh token to revoke is read from the HttpOnly `refresh_token` cookie
// (no request body). The access token is still authenticated via the
// Authorization: Bearer header by the Auth middleware. On success the cookie is
// cleared. Logout is idempotent — a missing/invalid cookie still returns 204.
func (h *AuthHandler) Logout(c *gin.Context) {
	// Drain and bound any request body so a large/streamed body cannot be used as a
	// DoS vector; the body is intentionally unused (token comes from the cookie).
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxBodyBytes)
	if c.Request.Body != nil {
		_, _ = io.Copy(io.Discard, c.Request.Body)
	}

	if _, ok := middleware.ClaimsFromCtx(c); !ok {
		httpx.ErrCode(c, http.StatusUnauthorized, "UNAUTHORIZED", "authentication required")
		return
	}

	// Read the refresh token from the cookie. A missing cookie is fine (idempotent
	// logout); we still clear the cookie and return 204.
	token, err := c.Cookie(refreshCookieName)
	if err == nil && token != "" {
		// Logout runs synchronously on the request context: it is a single fast DB
		// revoke and we want the 204 to confirm the revoke actually happened. The
		// revoke is idempotent, so a client disconnect mid-write is harmless.
		if revokeErr := h.auth.Logout(c.Request.Context(), token); revokeErr != nil {
			// Idempotent: even invalid tokens return 204.
			slog.Warn("logout: could not revoke token", "err", revokeErr)
		}
	}

	// Always clear the cookie so the browser drops it even if there was nothing to
	// revoke server-side.
	clearRefreshCookie(c, h.cookieDomain)

	httpx.NoContent(c)
}

// ForgotPasswordRequest is the forgot-password endpoint request body.
type ForgotPasswordRequest struct {
	Email string `json:"email" binding:"required,email,max=254"`
}

// forgotPasswordMessage is the constant, enumeration-safe response message.
//
//nolint:gosec // G101 false positive: this is a UI response message, not a credential or password value
const forgotPasswordMessage = "If an account exists for that email, a password reset link has been sent."

// ForgotPassword handles POST /v1/auth/forgot-password.
// ALWAYS returns 202 with a constant message regardless of account existence or
// state (no enumeration). The actual send (if any) happens in the service.
func (h *AuthHandler) ForgotPassword(c *gin.Context) {
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxBodyBytes)

	var req ForgotPasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		httpx.ErrCode(c, http.StatusBadRequest, "VALIDATION_ERROR", err.Error())
		return
	}

	// Fire-and-forget at the response level: the service swallows all outcomes so
	// the response is identical whether or not anything was sent.
	h.auth.ForgotPassword(c.Request.Context(), req.Email)

	httpx.Accepted(c, gin.H{"message": forgotPasswordMessage})
}

// ResetPasswordRequest is the reset-password endpoint request body.
type ResetPasswordRequest struct {
	Token       string `json:"token" binding:"required,max=512"`
	NewPassword string `json:"newPassword" binding:"required,min=12,max=128"`
}

// ResetPassword handles POST /v1/auth/reset-password.
// Returns 200 {"reset":true} on success, 400 INVALID_RESET_TOKEN on bad/expired
// token, 422 WEAK_PASSWORD if the new password is too weak.
func (h *AuthHandler) ResetPassword(c *gin.Context) {
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxBodyBytes)

	var req ResetPasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		httpx.ErrCode(c, http.StatusBadRequest, "VALIDATION_ERROR", err.Error())
		return
	}

	if err := h.auth.ResetPassword(c.Request.Context(), req.Token, req.NewPassword); err != nil {
		httpx.Err(c, err)
		return
	}

	httpx.OK(c, gin.H{"reset": true})
}
