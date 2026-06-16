package handler

import (
	"net/http"

	"github.com/CoverOnes/user/internal/domain"
	"github.com/CoverOnes/user/internal/platform/httpx"
	"github.com/CoverOnes/user/internal/service"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// PublicProfileHandler handles the unauthenticated GET /v1/users/:userId/profile.
//
// PII-SAFE GUARANTEE: this endpoint returns ONLY the explicit 12-field projection
// built by publicProfile(). It NEVER serializes *domain.User directly, so PII
// columns (email, legal_name_enc, national_id_enc, password_hash, status,
// company_id, email_verified, token_version, mfa*, updated_at, deleted_at) can
// never leak even if new fields are added to domain.User later.
type PublicProfileHandler struct {
	profile *service.ProfileService
}

// NewPublicProfileHandler returns a PublicProfileHandler.
func NewPublicProfileHandler(profile *service.ProfileService) *PublicProfileHandler {
	return &PublicProfileHandler{profile: profile}
}

// Get handles GET /v1/users/:userId/profile (public, no auth).
func (h *PublicProfileHandler) Get(c *gin.Context) {
	id, err := uuid.Parse(c.Param("userId"))
	if err != nil {
		httpx.ErrCode(c, http.StatusBadRequest, "INVALID_USER_ID", "userId must be a valid UUID")
		return
	}

	u, err := h.profile.GetByID(c.Request.Context(), id)
	if err != nil {
		// domain.ErrNotFound → 404 USER_NOT_FOUND; any other → 500.
		httpx.Err(c, err)
		return
	}

	httpx.OK(c, publicProfile(u))
}

// publicProfile builds the EXPLICIT PII-safe 12-field projection for a user. This
// is the single source of truth for the public field set; both the public handler
// and the authed own-profile handler use it (the own view adds only email, which
// is the user's own data, not a leak). Keeping this an allowlist — rather than
// serializing the struct and stripping fields — means a newly added domain.User
// column is excluded by default.
func publicProfile(u *domain.User) gin.H {
	return gin.H{
		"id":          u.ID,
		"handle":      u.Handle,
		"displayName": u.DisplayName,
		"headline":    u.Headline,
		"bio":         u.Bio,
		"location":    u.Location,
		"avatarUrl":   u.AvatarURL,
		"coverUrl":    u.CoverURL,
		"accountType": u.AccountType,
		"verified":    u.KYCTier >= 1, // DERIVED: tier-1+ accounts show a verified badge.
		"kycTier":     u.KYCTier,
		"joinedAt":    u.CreatedAt,
	}
}
