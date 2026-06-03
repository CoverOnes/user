package handler

import (
	"context"
	"log/slog"
	"net/http"
	"time"

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

	// Detached context so this security-critical revoke write completes even if the client
	// disconnects mid-request (request cancellation must not abort a session-revocation —
	// backend-security-design §5). Bounded by a short timeout so it cannot hang.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(c.Request.Context()), 5*time.Second)
	defer cancel()
	if err := h.auth.LogoutAll(ctx, userID); err != nil {
		slog.Warn("revoke_all: failed to bump token_version", "userId", userID, "err", err)
		httpx.Err(c, err)

		return
	}

	httpx.NoContent(c)
}
