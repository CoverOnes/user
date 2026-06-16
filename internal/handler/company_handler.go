package handler

import (
	"net/http"

	"github.com/CoverOnes/user/internal/domain"
	"github.com/CoverOnes/user/internal/platform/httpx"
	"github.com/CoverOnes/user/internal/service"
	"github.com/CoverOnes/user/internal/store"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// CompanyHandler handles the authed /v1/me/company surface (P4 Company).
//
// PII GUARANTEE: the OWNER view (/v1/me/company) is the ONLY place registration_no
// is exposed — it is the caller's own company data, not a leak. The public
// projections (companyPublic / companyMember, used by PublicCompanyHandler) NEVER
// include registration_no or owner_user_id.
type CompanyHandler struct {
	companies *service.CompanyService
}

// NewCompanyHandler returns a CompanyHandler.
func NewCompanyHandler(companies *service.CompanyService) *CompanyHandler {
	return &CompanyHandler{companies: companies}
}

// PublicCompanyHandler handles the unauthenticated /v1/companies/:companyId surface
// (GET company + GET members).
//
// PII-SAFE GUARANTEE: both endpoints return ONLY explicit projections
// (companyPublic / companyMember). They NEVER serialize *domain.Company or
// *domain.User directly, so registration_no / owner_user_id (company) and email /
// national_id / kyc_tier / status (members) can never leak even if new fields are
// added to those structs later.
type PublicCompanyHandler struct {
	companies *service.CompanyService
}

// NewPublicCompanyHandler returns a PublicCompanyHandler.
func NewPublicCompanyHandler(companies *service.CompanyService) *PublicCompanyHandler {
	return &PublicCompanyHandler{companies: companies}
}

// companyPublic builds the EXPLICIT PII-safe projection of a company for PUBLIC
// consumers. registration_no and owner_user_id are deliberately EXCLUDED. This is
// the single source of truth for the public company field set (allowlist), so a new
// domain.Company column is excluded by default. Takes a pointer to avoid copying the
// (heavy) struct (gocritic hugeParam).
func companyPublic(c *domain.Company) gin.H {
	return gin.H{
		"id":          c.ID,
		"handle":      c.Handle,
		"name":        c.Name,
		"tagline":     c.Tagline,
		"about":       c.About,
		"location":    c.Location,
		"website":     c.Website,
		"industry":    c.Industry,
		"companySize": c.CompanySize,
		"foundedYear": c.FoundedYear,
		"logoUrl":     c.LogoURL,
		"coverUrl":    c.CoverURL,
		"status":      c.Status,
		"createdAt":   c.CreatedAt,
	}
}

// companyOwnerView extends the public projection with registrationNo — the OWNER's
// own data, surfaced ONLY by /v1/me/company. owner_user_id stays excluded (the
// caller already knows they are the owner; it is not part of the contract).
func companyOwnerView(c *domain.Company) gin.H {
	v := companyPublic(c)
	v["registrationNo"] = c.RegistrationNo

	return v
}

// companyMember builds the EXPLICIT PII-safe card for a company team-roster entry.
// It lists ONLY non-PII display columns (email / national_id / kyc_tier / status are
// absent). Takes a pointer to avoid copying the carrier (gocritic hugeParam).
func companyMember(m *store.CompanyMember) gin.H {
	return gin.H{
		"userId":      m.UserID,
		"displayName": m.DisplayName,
		"handle":      m.Handle,
		"headline":    m.Headline,
		"avatarUrl":   m.AvatarURL,
		"isOwner":     m.IsOwner,
	}
}

// Get handles GET /v1/me/company (authed) → 200 {data: MyCompany} (owner view incl.
// registrationNo). The caller with no company_id → 404 COMPANY_NOT_FOUND.
func (h *CompanyHandler) Get(c *gin.Context) {
	uid, ok := callerID(c)
	if !ok {
		return
	}

	company, err := h.companies.GetMyCompany(c.Request.Context(), uid)
	if err != nil {
		httpx.Err(c, err)
		return
	}

	httpx.OK(c, companyOwnerView(company))
}

// UpdateCompanyRequest is the PUT /v1/me/company body. Full-replace of editable
// fields; name is required. Per-field length/format limits are validated in the
// service layer (NOT binding tags, except name whose bounds mirror the service check)
// so the error envelope is consistent VALIDATION_ERROR / HANDLE_TAKEN.
type UpdateCompanyRequest struct {
	Name        string  `json:"name" binding:"required,min=1,max=200"`
	Handle      *string `json:"handle"`
	Tagline     *string `json:"tagline"`
	About       *string `json:"about"`
	Location    *string `json:"location"`
	Website     *string `json:"website"`
	Industry    *string `json:"industry"`
	CompanySize *string `json:"companySize"`
	FoundedYear *int16  `json:"foundedYear"`
	LogoURL     *string `json:"logoUrl"`
	CoverURL    *string `json:"coverUrl"`
}

// Update handles PUT /v1/me/company (authed + RequireTier(1)). OWNER-GATED in the
// service: a non-owner caller → 403 NOT_COMPANY_OWNER. → 200 {data: CompanyProfile}.
func (h *CompanyHandler) Update(c *gin.Context) {
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxBodyBytes)

	uid, ok := callerID(c)
	if !ok {
		return
	}

	var req UpdateCompanyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		httpx.ErrCode(c, http.StatusBadRequest, "VALIDATION_ERROR", err.Error())
		return
	}

	company, err := h.companies.UpdateMyCompany(c.Request.Context(), &service.UpdateCompanyInput{
		CallerID:    uid,
		Name:        req.Name,
		Handle:      req.Handle,
		Tagline:     req.Tagline,
		About:       req.About,
		Location:    req.Location,
		Website:     req.Website,
		Industry:    req.Industry,
		CompanySize: req.CompanySize,
		FoundedYear: req.FoundedYear,
		LogoURL:     req.LogoURL,
		CoverURL:    req.CoverURL,
	})
	if err != nil {
		httpx.Err(c, err)
		return
	}

	// 200 returns the PUBLIC projection (no registrationNo) per the frozen contract
	// (PUT → CompanyProfile, not MyCompany). The owner re-fetches /me/company for the
	// registrationNo-bearing view.
	httpx.OK(c, companyPublic(company))
}

// Get handles GET /v1/companies/:companyId (public, no auth) → 200 {data:
// CompanyProfile}. 400 INVALID_COMPANY_ID (bad uuid); 404 COMPANY_NOT_FOUND.
func (h *PublicCompanyHandler) Get(c *gin.Context) {
	id, err := uuid.Parse(c.Param("companyId"))
	if err != nil {
		httpx.ErrCode(c, http.StatusBadRequest, "INVALID_COMPANY_ID", "companyId must be a valid UUID")
		return
	}

	company, err := h.companies.GetByID(c.Request.Context(), id)
	if err != nil {
		httpx.Err(c, err)
		return
	}

	httpx.OK(c, companyPublic(company))
}

// Members handles GET /v1/companies/:companyId/members (public) → 200
// {data:{members: CompanyMember[]}}. Empty roster → {members:[]}. 400
// INVALID_COMPANY_ID on a malformed uuid.
func (h *PublicCompanyHandler) Members(c *gin.Context) {
	id, err := uuid.Parse(c.Param("companyId"))
	if err != nil {
		httpx.ErrCode(c, http.StatusBadRequest, "INVALID_COMPANY_ID", "companyId must be a valid UUID")
		return
	}

	rows, err := h.companies.ListMembers(c.Request.Context(), id)
	if err != nil {
		httpx.Err(c, err)
		return
	}

	members := make([]gin.H, 0, len(rows))
	for i := range rows {
		members = append(members, companyMember(&rows[i]))
	}

	httpx.OK(c, gin.H{"members": members})
}
