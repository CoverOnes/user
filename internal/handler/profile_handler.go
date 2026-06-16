package handler

import (
	"net/http"

	"github.com/CoverOnes/user/internal/domain"
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

	httpx.OK(c, ownProfile(u))
}

// ownProfile builds the OwnProfile envelope: the PII-safe public projection plus
// the user's own email (own data, not a leak). All other PII columns stay excluded
// because publicProfile is an explicit allowlist.
func ownProfile(u *domain.User) gin.H {
	p := publicProfile(u)
	p["email"] = u.Email

	return p
}

// UpdateProfileRequest is the PUT /v1/me/profile request body. Semantics = full
// replace of the editable fields (the frontend sends the complete set). Per-field
// length/format limits are validated in the service layer (NOT via binding tags,
// except displayName whose bounds mirror the service check) so the error envelope
// is consistent VALIDATION_ERROR / HANDLE_TAKEN.
type UpdateProfileRequest struct {
	DisplayName string  `json:"displayName" binding:"required,min=1,max=80"`
	Handle      *string `json:"handle"`
	Headline    *string `json:"headline"`
	Bio         *string `json:"bio"`
	Location    *string `json:"location"`
	AvatarURL   *string `json:"avatarUrl"`
	CoverURL    *string `json:"coverUrl"`
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

	u, err := h.profile.UpdateProfile(c.Request.Context(), &service.UpdateProfileInput{
		UserID:      id,
		DisplayName: req.DisplayName,
		Handle:      req.Handle,
		Headline:    req.Headline,
		Bio:         req.Bio,
		Location:    req.Location,
		AvatarURL:   req.AvatarURL,
		CoverURL:    req.CoverURL,
	})
	if err != nil {
		httpx.Err(c, err)
		return
	}

	httpx.OK(c, ownProfile(u))
}
