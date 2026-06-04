package handler

import (
	"net/http"

	"github.com/CoverOnes/user/internal/platform/httpx"
	"github.com/CoverOnes/user/internal/platform/middleware"
	"github.com/CoverOnes/user/internal/service"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// MeHandler handles GET /v1/me.
type MeHandler struct {
	profile *service.ProfileService
}

// NewMeHandler returns a MeHandler.
func NewMeHandler(profile *service.ProfileService) *MeHandler {
	return &MeHandler{profile: profile}
}

// Get handles GET /v1/me.
func (h *MeHandler) Get(c *gin.Context) {
	claims, ok := middleware.ClaimsFromCtx(c)
	if !ok {
		httpx.ErrCode(c, http.StatusUnauthorized, "UNAUTHORIZED", "authentication required")
		return
	}

	id, err := uuid.Parse(claims.Subject)
	if err != nil {
		httpx.ErrCode(c, http.StatusUnauthorized, "UNAUTHORIZED", "invalid token subject")
		return
	}

	u, err := h.profile.GetByID(c.Request.Context(), id)
	if err != nil {
		httpx.Err(c, err)
		return
	}

	httpx.OK(c, gin.H{
		"id":            u.ID,
		"email":         u.Email,
		"displayName":   u.DisplayName,
		"avatarUrl":     u.AvatarURL,
		"accountType":   u.AccountType,
		"kycTier":       u.KYCTier,
		"status":        u.Status,
		"companyId":     u.CompanyID,
		"emailVerified": u.EmailVerified,
		"createdAt":     u.CreatedAt,
	})
}
