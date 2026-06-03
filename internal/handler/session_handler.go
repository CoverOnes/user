package handler

import (
	"log/slog"
	"net/http"

	"github.com/CoverOnes/user/internal/platform/httpx"
	"github.com/CoverOnes/user/internal/platform/middleware"
	"github.com/CoverOnes/user/internal/service"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// SessionHandler handles session-management endpoints.
type SessionHandler struct {
	auth *service.AuthService
}

// NewSessionHandler returns a SessionHandler.
func NewSessionHandler(auth *service.AuthService) *SessionHandler {
	return &SessionHandler{auth: auth}
}

// RevokeAll handles POST /v1/me/sessions/revoke-all.
// It bumps token_version for the authenticated user, invalidating all existing
// refresh tokens immediately (they fail the server-side version check on next use).
func (h *SessionHandler) RevokeAll(c *gin.Context) {
	claims, ok := middleware.ClaimsFromCtx(c)
	if !ok {
		httpx.ErrCode(c, http.StatusUnauthorized, "UNAUTHORIZED", "authentication required")
		return
	}

	userID, err := uuid.Parse(claims.Subject)
	if err != nil {
		httpx.ErrCode(c, http.StatusUnauthorized, "UNAUTHORIZED", "invalid token subject")
		return
	}

	// Run in a detached context so DB write is not canceled if the client disconnects —
	// goroutine safety per backend-security-design §5 (request context must not govern
	// side-effecting writes). We block here since the operation is fast.
	if err := h.auth.LogoutAll(c.Request.Context(), userID); err != nil {
		slog.Warn("revoke_all: failed to bump token_version", "userId", userID, "err", err)
		httpx.Err(c, err)

		return
	}

	httpx.NoContent(c)
}
