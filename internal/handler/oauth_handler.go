package handler

import (
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/CoverOnes/user/internal/domain"
	"github.com/CoverOnes/user/internal/platform/httpx"
	"github.com/CoverOnes/user/internal/platform/middleware"
	"github.com/CoverOnes/user/internal/service"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// maxOAuthBodyBytes caps the OAuth exchange request body (small JSON object).
const maxOAuthBodyBytes = 8 << 10 // 8 KiB

// OAuthHandler handles the OAuth social login endpoints.
type OAuthHandler struct {
	svc                  *service.OAuthService
	frontendPostLoginURL string
}

// NewOAuthHandler returns an OAuthHandler.
func NewOAuthHandler(svc *service.OAuthService, frontendPostLoginURL string) *OAuthHandler {
	return &OAuthHandler{svc: svc, frontendPostLoginURL: frontendPostLoginURL}
}

// Start handles GET /v1/auth/oauth/:provider/start.
// It returns a JSON body with the provider authorization URL so the frontend
// can redirect the browser (no direct 302 here to keep CORS simple).
func (h *OAuthHandler) Start(c *gin.Context) {
	provider := strings.ToLower(c.Param("provider"))

	result, err := h.svc.Start(c.Request.Context(), provider)
	if err != nil {
		httpx.Err(c, err)
		return
	}

	httpx.OK(c, gin.H{"authorizeUrl": result.AuthorizeURL})
}

// Callback handles GET /v1/auth/oauth/:provider/callback.
// Both login and bind flows redirect to this URL; HandleCallback distinguishes
// them internally by inspecting the Redis state entry's ForBind field.
//
// On login/new-user success it issues a 302 to ${frontendPostLoginURL}?code=<oneTimeCode>.
// On bind success it issues a 302 to ${frontendPostLoginURL}?bind=success.
// On email collision it redirects to ${frontendPostLoginURL}?error=email_exists.
func (h *OAuthHandler) Callback(c *gin.Context) {
	provider := strings.ToLower(c.Param("provider"))
	code := c.Query("code")
	state := c.Query("state")

	if code == "" || state == "" {
		c.Redirect(http.StatusFound, h.frontendPostLoginURL+"?error=invalid_request")
		return
	}

	result, err := h.svc.HandleCallback(c.Request.Context(), provider, code, state)
	if err != nil {
		// Map domain errors to redirect error codes.
		redirectErr := "server_error"

		switch {
		case errors.Is(err, domain.ErrOAuthStateInvalid):
			redirectErr = "invalid_state"
		case errors.Is(err, domain.ErrOAuthExchangeFailed):
			redirectErr = "exchange_failed"
		case errors.Is(err, domain.ErrOAuthProviderUnknown):
			redirectErr = "unknown_provider"
		case errors.Is(err, domain.ErrAccountSuspended):
			redirectErr = "account_suspended"
		case errors.Is(err, domain.ErrIdentityAlreadyBound):
			redirectErr = "identity_already_bound"
		}

		c.Redirect(http.StatusFound, h.frontendPostLoginURL+"?error="+redirectErr)

		return
	}

	switch result.Outcome {
	case service.CallbackEmailCollision:
		c.Redirect(http.StatusFound, h.frontendPostLoginURL+"?error=email_exists")
	case service.CallbackBindSuccess:
		// Bind flow: redirect to frontend post-login URL with bind=success indicator.
		// No one-time code is issued for bind — the user is already authenticated.
		c.Redirect(http.StatusFound, h.frontendPostLoginURL+"?bind=success")
	default:
		// CallbackLogin and CallbackNewUser both carry a one-time code.
		// Tokens NEVER go in the URL; only the short-lived opaque code does.
		c.Redirect(http.StatusFound, h.frontendPostLoginURL+"?code="+result.OneTimeCode)
	}
}

// exchangeRequest is the POST /v1/auth/oauth/exchange request body.
type exchangeRequest struct {
	Code string `json:"code" binding:"required"`
}

// Exchange handles POST /v1/auth/oauth/exchange.
// It consumes a one-time login code and returns a full token pair.
func (h *OAuthHandler) Exchange(c *gin.Context) {
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxOAuthBodyBytes)

	var req exchangeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		httpx.ErrCode(c, http.StatusBadRequest, "VALIDATION_ERROR", err.Error())
		return
	}

	pair, err := h.svc.Exchange(c.Request.Context(), req.Code)
	if err != nil {
		httpx.Err(c, err)
		return
	}

	httpx.OK(c, gin.H{
		"accessToken":  pair.AccessToken,
		"refreshToken": pair.RefreshToken,
		"expiresIn":    pair.ExpiresIn,
	})
}

// BindStart handles POST /v1/me/identities/:provider (authenticated).
// Initiates the bind flow and returns the authorization URL.
func (h *OAuthHandler) BindStart(c *gin.Context) {
	provider := strings.ToLower(c.Param("provider"))

	claims, ok := middleware.ClaimsFromCtx(c)
	if !ok {
		httpx.Err(c, domain.ErrUnauthorized)
		return
	}

	userID, err := uuid.Parse(claims.Subject)
	if err != nil {
		httpx.Err(c, domain.ErrUnauthorized)
		return
	}

	// Drain and discard body so any body content is consumed (safe with MaxBytesReader).
	if c.Request.Body != nil {
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxOAuthBodyBytes)
		_, _ = io.Copy(io.Discard, c.Request.Body)
	}

	result, err := h.svc.BindStart(c.Request.Context(), provider, userID)
	if err != nil {
		httpx.Err(c, err)
		return
	}

	httpx.OK(c, gin.H{"authorizeUrl": result.AuthorizeURL})
}

// Unbind handles DELETE /v1/me/identities/:provider (authenticated).
func (h *OAuthHandler) Unbind(c *gin.Context) {
	provider := strings.ToLower(c.Param("provider"))

	claims, ok := middleware.ClaimsFromCtx(c)
	if !ok {
		httpx.Err(c, domain.ErrUnauthorized)
		return
	}

	userID, err := uuid.Parse(claims.Subject)
	if err != nil {
		httpx.Err(c, domain.ErrUnauthorized)
		return
	}

	if err := h.svc.Unbind(c.Request.Context(), userID, provider); err != nil {
		httpx.Err(c, err)
		return
	}

	httpx.NoContent(c)
}
