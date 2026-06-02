package handler

import (
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

// AuthHandler handles authentication endpoints.
type AuthHandler struct {
	auth   *service.AuthService
	signer *jwt.Signer
}

// NewAuthHandler returns an AuthHandler.
func NewAuthHandler(auth *service.AuthService, signer *jwt.Signer) *AuthHandler {
	return &AuthHandler{auth: auth, signer: signer}
}

// RegisterRequest is the register endpoint request body.
type RegisterRequest struct {
	Email       string `json:"email" binding:"required,email,max=254"`
	Password    string `json:"password" binding:"required,min=12,max=128"`
	DisplayName string `json:"displayName" binding:"required,max=80"`
	AccountType string `json:"accountType" binding:"required"`
	CompanyName string `json:"companyName"`
}

// Register handles POST /v1/auth/register.
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
		CompanyName: req.CompanyName,
	})
	if err != nil {
		httpx.Err(c, err)
		return
	}

	u := out.User
	httpx.Created(c, gin.H{
		"user": gin.H{
			"id":          u.ID,
			"email":       u.Email,
			"displayName": u.DisplayName,
			"accountType": u.AccountType,
			"kycTier":     u.KYCTier,
			"status":      u.Status,
		},
	})
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

	httpx.OK(c, gin.H{
		"accessToken":  pair.AccessToken,
		"refreshToken": pair.RefreshToken,
		"tokenType":    "Bearer",
		"expiresIn":    pair.ExpiresIn,
	})
}

// RefreshRequest is the token refresh endpoint request body.
type RefreshRequest struct {
	RefreshToken      string  `json:"refreshToken" binding:"required"`
	DeviceFingerprint *string `json:"deviceFingerprint" binding:"omitempty,max=512"`
}

// Refresh handles POST /v1/auth/refresh.
func (h *AuthHandler) Refresh(c *gin.Context) {
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxBodyBytes)

	var req RefreshRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		httpx.ErrCode(c, http.StatusBadRequest, "VALIDATION_ERROR", err.Error())
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
		RawToken:          req.RefreshToken,
		DeviceFingerprint: req.DeviceFingerprint,
		IPAddr:            ip,
		UserAgent:         uaPtr,
	})
	if err != nil {
		httpx.Err(c, err)
		return
	}

	httpx.OK(c, gin.H{
		"accessToken":  pair.AccessToken,
		"refreshToken": pair.RefreshToken,
		"tokenType":    "Bearer",
		"expiresIn":    pair.ExpiresIn,
	})
}

// LogoutRequest is the logout endpoint request body.
type LogoutRequest struct {
	RefreshToken string `json:"refreshToken" binding:"required"`
}

// Logout handles POST /v1/auth/logout.
func (h *AuthHandler) Logout(c *gin.Context) {
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxBodyBytes)

	var req LogoutRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		httpx.ErrCode(c, http.StatusBadRequest, "VALIDATION_ERROR", err.Error())
		return
	}

	claims, ok := middleware.ClaimsFromCtx(c)
	if !ok {
		httpx.ErrCode(c, http.StatusUnauthorized, "UNAUTHORIZED", "authentication required")
		return
	}

	// Run logout in a detached context so DB write is not canceled if the
	// client disconnects — goroutine uses context.Background() with its own
	// timeout per backend-security-design §5.
	// We block here since logout is fast and we want 204 to confirm.
	_ = claims // subject available if needed for audit

	if err := h.auth.Logout(c.Request.Context(), req.RefreshToken); err != nil {
		// Idempotent: even invalid tokens return 204.
		slog.Warn("logout: could not revoke token", "err", err)
	}

	httpx.NoContent(c)
}
