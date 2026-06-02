package handler

import (
	"net/http"

	"github.com/CoverOnes/user/internal/platform/httpx"
	"github.com/CoverOnes/user/internal/platform/middleware"
	"github.com/CoverOnes/user/internal/service"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// ProfileHandler handles GET and PUT /v1/me/profile.
type ProfileHandler struct {
	profile *service.ProfileService
}

// NewProfileHandler returns a ProfileHandler.
func NewProfileHandler(profile *service.ProfileService) *ProfileHandler {
	return &ProfileHandler{profile: profile}
}

// Get handles GET /v1/me/profile.
func (h *ProfileHandler) Get(c *gin.Context) {
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
		"displayName": u.DisplayName,
		"avatarUrl":   u.AvatarURL,
	})
}

// UpdateProfileRequest is the PUT /v1/me/profile request body.
type UpdateProfileRequest struct {
	DisplayName string  `json:"displayName" binding:"required,min=1,max=80"`
	AvatarURL   *string `json:"avatarUrl"`
}

// Update handles PUT /v1/me/profile.
func (h *ProfileHandler) Update(c *gin.Context) {
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxBodyBytes)

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

	var req UpdateProfileRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		httpx.ErrCode(c, http.StatusBadRequest, "VALIDATION_ERROR", err.Error())
		return
	}

	u, err := h.profile.UpdateProfile(c.Request.Context(), service.UpdateProfileInput{
		UserID:      id,
		DisplayName: req.DisplayName,
		AvatarURL:   req.AvatarURL,
	})
	if err != nil {
		httpx.Err(c, err)
		return
	}

	httpx.OK(c, gin.H{
		"displayName": u.DisplayName,
		"avatarUrl":   u.AvatarURL,
	})
}
