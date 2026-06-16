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

// SavedHandler handles the /v1/me/saved surface (P4 Saved bookmarks).
//
// PII-SAFE GUARANTEE: saved-company cards are built from store.SavedCompanyRow, whose
// projection is an explicit non-PII allowlist (no registration_no / owner_user_id /
// status). The handler never serializes a *domain.Company, so a new sensitive column
// on the company row can never leak through a saved list even if added later. Saved
// 'job' items carry no PII (just a uuid reference the FE hydrates from marketplace).
type SavedHandler struct {
	saved *service.SavedService
}

// NewSavedHandler returns a SavedHandler.
func NewSavedHandler(saved *service.SavedService) *SavedHandler {
	return &SavedHandler{saved: saved}
}

// parseItemType validates a raw item_type against the value allowlist, writing a 400
// VALIDATION_ERROR envelope and returning ok=false on an unknown / empty value.
func parseItemType(c *gin.Context, raw string) (string, bool) {
	if raw != domain.SavedItemTypeJob && raw != domain.SavedItemTypeCompany {
		httpx.ErrCode(c, http.StatusBadRequest, "VALIDATION_ERROR", "type must be 'job' or 'company'")
		return "", false
	}

	return raw, true
}

// parseItemID validates a raw item id as a UUID, writing a 400 VALIDATION_ERROR
// envelope and returning ok=false on a malformed value.
func parseItemID(c *gin.Context, raw string) (uuid.UUID, bool) {
	id, err := uuid.Parse(raw)
	if err != nil {
		httpx.ErrCode(c, http.StatusBadRequest, "VALIDATION_ERROR", "itemId must be a valid UUID")
		return uuid.Nil, false
	}

	return id, true
}

// savedJobRef is the bare-reference shape for a saved 'job' bookmark. The FE hydrates
// the display fields (title, budget, …) via marketplaceApi.getListing(itemId) — the
// backend never cross-calls the delegated marketplace service.
func savedJobRef(si *domain.SavedItem) gin.H {
	return gin.H{
		"savedId":  si.ID,
		"itemType": domain.SavedItemTypeJob,
		"itemId":   si.ItemID,
		"savedAt":  si.CreatedAt,
	}
}

// savedCompanyCard is the PII-safe saved-'company' card: the bookmark reference plus
// the in-service company public projection. It is the single source of truth for the
// exposed field set (explicit allowlist — no registration_no / owner_user_id /
// status). Takes a pointer to avoid copying the (heavy) carrier struct (gocritic
// hugeParam).
func savedCompanyCard(r *store.SavedCompanyRow) gin.H {
	return gin.H{
		"savedId":  r.SavedID,
		"itemType": domain.SavedItemTypeCompany,
		"itemId":   r.CompanyID,
		"savedAt":  r.SavedAt,
		"company": gin.H{
			"id":          r.CompanyID,
			"handle":      r.Handle,
			"name":        r.Name,
			"tagline":     r.Tagline,
			"location":    r.Location,
			"industry":    r.Industry,
			"companySize": r.CompanySize,
			"logoUrl":     r.LogoURL,
		},
	}
}

// List handles GET /v1/me/saved?type=job|company → {data:{items:[...]}}.
// For type=job items are bare refs; for type=company items carry the PII-safe company
// projection (a saved company whose row is gone is skipped server-side). Empty list →
// {items:[]}. The required `type` query param drives the branch.
func (h *SavedHandler) List(c *gin.Context) {
	uid, ok := callerID(c)
	if !ok {
		return
	}

	itemType, ok := parseItemType(c, c.Query("type"))
	if !ok {
		return
	}

	if itemType == domain.SavedItemTypeJob {
		refs, err := h.saved.ListJobs(c.Request.Context(), uid)
		if err != nil {
			httpx.Err(c, err)
			return
		}

		items := make([]gin.H, 0, len(refs))
		for i := range refs {
			items = append(items, savedJobRef(&refs[i]))
		}

		httpx.OK(c, gin.H{"items": items})

		return
	}

	rows, err := h.saved.ListCompanies(c.Request.Context(), uid)
	if err != nil {
		httpx.Err(c, err)
		return
	}

	items := make([]gin.H, 0, len(rows))
	for i := range rows {
		items = append(items, savedCompanyCard(&rows[i]))
	}

	httpx.OK(c, gin.H{"items": items})
}

// saveRequest is the POST /v1/me/saved body. Identity (the owner of the bookmark) is
// the JWT subject; the body carries ONLY the target (itemType + itemId).
type saveRequest struct {
	ItemType string `json:"itemType" binding:"required"`
	ItemID   string `json:"itemId"   binding:"required"`
}

// Save handles POST /v1/me/saved → 201 {data:{savedId,itemType,itemId,savedAt}}.
// A duplicate live bookmark → 409 SAVED_ITEM_EXISTS; a non-resolving company target →
// 404 SAVED_TARGET_NOT_FOUND (job targets are not existence-checked).
func (h *SavedHandler) Save(c *gin.Context) {
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxBodyBytes)

	uid, ok := callerID(c)
	if !ok {
		return
	}

	var req saveRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		httpx.ErrCode(c, http.StatusBadRequest, "VALIDATION_ERROR", err.Error())
		return
	}

	itemType, ok := parseItemType(c, req.ItemType)
	if !ok {
		return
	}

	itemID, ok := parseItemID(c, req.ItemID)
	if !ok {
		return
	}

	si, err := h.saved.Save(c.Request.Context(), uid, itemType, itemID)
	if err != nil {
		httpx.Err(c, err)
		return
	}

	httpx.Created(c, gin.H{
		"savedId":  si.ID,
		"itemType": si.ItemType,
		"itemId":   si.ItemID,
		"savedAt":  si.CreatedAt,
	})
}

// Unsave handles DELETE /v1/me/saved?type=job|company&itemId=<uuid> →
// 200 {data:{itemType,itemId,removed}}. The delete is identity-scoped (caller's own
// bookmark) and IDEMPOTENT: removing an absent bookmark returns 200 {removed:false}
// (not 404) so the toggle UX survives a double-unsave race (resolved-decision #2).
func (h *SavedHandler) Unsave(c *gin.Context) {
	uid, ok := callerID(c)
	if !ok {
		return
	}

	itemType, ok := parseItemType(c, c.Query("type"))
	if !ok {
		return
	}

	itemID, ok := parseItemID(c, c.Query("itemId"))
	if !ok {
		return
	}

	removed, err := h.saved.Unsave(c.Request.Context(), uid, itemType, itemID)
	if err != nil {
		httpx.Err(c, err)
		return
	}

	httpx.OK(c, gin.H{
		"itemType": itemType,
		"itemId":   itemID,
		"removed":  removed,
	})
}
