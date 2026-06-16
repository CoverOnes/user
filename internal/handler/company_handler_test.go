package handler_test

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/CoverOnes/user/internal/auth/jwt"
	"github.com/CoverOnes/user/internal/domain"
	"github.com/CoverOnes/user/internal/handler"
	"github.com/CoverOnes/user/internal/platform/middleware"
	"github.com/CoverOnes/user/internal/service"
	"github.com/CoverOnes/user/internal/store"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// companyTestStore is an in-memory CompanyStore for CompanyHandler tests, with
// keyed companies + injectable members/errors. It is local to this file so the
// auth-handler tests' empty fakeCompanyStore is left untouched.
type companyTestStore struct {
	byID    map[uuid.UUID]*domain.Company
	members map[uuid.UUID][]store.CompanyMember

	getByIDErr     error
	updateErr      error
	listMembersErr error
}

func newCompanyTestStore() *companyTestStore {
	return &companyTestStore{
		byID:    make(map[uuid.UUID]*domain.Company),
		members: make(map[uuid.UUID][]store.CompanyMember),
	}
}

func (f *companyTestStore) put(c *domain.Company) {
	cp := *c
	f.byID[c.ID] = &cp
}

func (f *companyTestStore) Create(_ context.Context, c *domain.Company) error {
	f.put(c)

	return nil
}

func (f *companyTestStore) GetByID(_ context.Context, id uuid.UUID) (*domain.Company, error) {
	if f.getByIDErr != nil {
		return nil, f.getByIDErr
	}
	c, ok := f.byID[id]
	if !ok {
		return nil, domain.ErrNotFound
	}

	return c, nil
}

func (f *companyTestStore) Update(_ context.Context, id uuid.UUID, in *store.CompanyUpdate) error {
	if f.updateErr != nil {
		return f.updateErr
	}
	c, ok := f.byID[id]
	if !ok {
		return domain.ErrCompanyNotFound
	}
	c.Name = in.Name
	c.Handle = in.Handle
	c.Tagline = in.Tagline
	c.About = in.About
	c.Location = in.Location
	c.Website = in.Website
	c.Industry = in.Industry
	c.CompanySize = in.CompanySize
	c.FoundedYear = in.FoundedYear
	c.LogoURL = in.LogoURL
	c.CoverURL = in.CoverURL

	return nil
}

func (f *companyTestStore) ListMembers(_ context.Context, companyID uuid.UUID) ([]store.CompanyMember, error) {
	if f.listMembersErr != nil {
		return nil, f.listMembersErr
	}

	return f.members[companyID], nil
}

// seedCompanyUser inserts a live user (account type / tier configurable) and links
// it to companyID. tier feeds the JWT (RequireTier(1) on PUT).
func seedCompanyUser(t *testing.T, users *fakeUserStore, email string, companyID *uuid.UUID, tier int16) *domain.User {
	t.Helper()

	now := time.Now().UTC()
	u := &domain.User{
		ID:          uuid.New(),
		Email:       email,
		DisplayName: "Company User",
		AccountType: domain.AccountTypeCompany,
		Status:      domain.UserStatusActive,
		KYCTier:     tier,
		CompanyID:   companyID,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	require.NoError(t, users.Create(context.Background(), u))

	return u
}

// buildCompanyRouter wires a Gin engine mirroring router.go for the company surface:
// a PUBLIC /v1/companies group (no auth) and a PROTECTED /v1/me/company group (Auth +
// RequireTier(1) on PUT), backed by one CompanyService over the supplied fakes.
func buildCompanyRouter(t *testing.T, users *fakeUserStore, companies *companyTestStore) (*gin.Engine, *jwt.Signer) {
	t.Helper()

	signer, err := jwt.NewEphemeralSigner(10 * time.Minute)
	require.NoError(t, err)

	svc := service.NewCompanyService(companies, users)

	r := gin.New()
	r.Use(middleware.Recover())

	pubCompanyH := handler.NewPublicCompanyHandler(svc)
	pub := r.Group("/v1/companies")
	pub.GET("/:companyId", pubCompanyH.Get)
	pub.GET("/:companyId/members", pubCompanyH.Members)

	companyH := handler.NewCompanyHandler(svc)
	me := r.Group("/v1/me")
	me.Use(middleware.Auth(signer))
	me.GET("/company", companyH.Get)
	me.PUT("/company", middleware.RequireTier(1), companyH.Update)

	return r, signer
}

// tokenForTier issues a JWT for u with an explicit kyc tier (RequireTier gate).
func tokenForTier(t *testing.T, signer *jwt.Signer, u *domain.User, tier int16) string {
	t.Helper()

	tok, err := signer.Issue(u.ID.String(), u.AccountType, tier, 0, true)
	require.NoError(t, err)

	return tok
}

// makeCompany builds and stores a company owned by ownerID with a registration_no.
func makeCompany(t *testing.T, companies *companyTestStore, ownerID uuid.UUID, name string) *domain.Company {
	t.Helper()

	now := time.Now().UTC()
	regNo := "REG-" + name
	c := &domain.Company{
		ID:             uuid.New(),
		Name:           name,
		RegistrationNo: &regNo,
		OwnerUserID:    ownerID,
		Status:         domain.CompanyStatusActive,
		CreatedAt:      now,
		UpdatedAt:      now,
	}
	companies.put(c)

	return c
}

// --- Public GET /v1/companies/:companyId ---

func TestPublicCompanyHandler_Get_PIISafe(t *testing.T) {
	users := newFakeUserStore()
	companies := newCompanyTestStore()
	owner := seedCompanyUser(t, users, "owner-pub@example.com", nil, 2)
	company := makeCompany(t, companies, owner.ID, "PublicCo")
	r, _ := buildCompanyRouter(t, users, companies)

	w := getJSON(t, r, "/v1/companies/"+company.ID.String())
	require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())

	data := rawDataMap(t, w)
	assert.Equal(t, "PublicCo", data["name"])
	assert.Equal(t, company.ID.String(), data["id"])

	// PII-safe: the public company projection MUST NOT expose registrationNo or owner_user_id.
	for _, leak := range []string{"registrationNo", "ownerUserId", "owner_user_id", "registration_no"} {
		_, present := data[leak]
		assert.Falsef(t, present, "public company must not leak %q", leak)
	}
}

func TestPublicCompanyHandler_Get_BadUUID(t *testing.T) {
	users := newFakeUserStore()
	companies := newCompanyTestStore()
	r, _ := buildCompanyRouter(t, users, companies)

	w := getJSON(t, r, "/v1/companies/not-a-uuid")
	require.Equal(t, http.StatusBadRequest, w.Code, "body: %s", w.Body.String())
	assert.Equal(t, "INVALID_COMPANY_ID", errCode(t, w))
}

func TestPublicCompanyHandler_Get_NotFound(t *testing.T) {
	users := newFakeUserStore()
	companies := newCompanyTestStore()
	r, _ := buildCompanyRouter(t, users, companies)

	w := getJSON(t, r, "/v1/companies/"+uuid.New().String())
	require.Equal(t, http.StatusNotFound, w.Code, "body: %s", w.Body.String())
	assert.Equal(t, "COMPANY_NOT_FOUND", errCode(t, w))
}

// --- Public GET /v1/companies/:companyId/members ---

func TestPublicCompanyHandler_Members_PIISafe(t *testing.T) {
	users := newFakeUserStore()
	companies := newCompanyTestStore()
	owner := seedCompanyUser(t, users, "owner-mem@example.com", nil, 2)
	company := makeCompany(t, companies, owner.ID, "MemberCo")
	companies.members[company.ID] = []store.CompanyMember{
		{UserID: owner.ID, DisplayName: "Owner", Handle: strp("owner"), Headline: strp("CEO"), AvatarURL: strp("https://cdn.example.com/o.png"), IsOwner: true},
		{UserID: uuid.New(), DisplayName: "Staff", Handle: strp("staff"), IsOwner: false},
	}
	r, _ := buildCompanyRouter(t, users, companies)

	w := getJSON(t, r, "/v1/companies/"+company.ID.String()+"/members")
	require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())

	data := rawDataMap(t, w)
	members, ok := data["members"].([]any)
	require.True(t, ok, "members must be an array")
	require.Len(t, members, 2)

	first, ok := members[0].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "Owner", first["displayName"])
	assert.Equal(t, true, first["isOwner"])

	// PII-safe: member cards MUST NOT carry email / national_id / kyc_tier / status.
	for _, leak := range []string{"email", "nationalId", "kycTier", "status", "legalName"} {
		_, present := first[leak]
		assert.Falsef(t, present, "member card must not leak %q", leak)
	}
}

func TestPublicCompanyHandler_Members_EmptyArrayNotNull(t *testing.T) {
	users := newFakeUserStore()
	companies := newCompanyTestStore()
	owner := seedCompanyUser(t, users, "owner-empty@example.com", nil, 2)
	company := makeCompany(t, companies, owner.ID, "EmptyCo")
	r, _ := buildCompanyRouter(t, users, companies)

	w := getJSON(t, r, "/v1/companies/"+company.ID.String()+"/members")
	require.Equal(t, http.StatusOK, w.Code)
	// Empty roster MUST serialize as [] not null (frontend contract).
	assert.Contains(t, w.Body.String(), `"members":[]`)
}

func TestPublicCompanyHandler_Members_BadUUID(t *testing.T) {
	users := newFakeUserStore()
	companies := newCompanyTestStore()
	r, _ := buildCompanyRouter(t, users, companies)

	w := getJSON(t, r, "/v1/companies/not-a-uuid/members")
	require.Equal(t, http.StatusBadRequest, w.Code)
	assert.Equal(t, "INVALID_COMPANY_ID", errCode(t, w))
}

// --- Authed GET /v1/me/company ---

func TestCompanyHandler_GetMyCompany_OwnerView(t *testing.T) {
	users := newFakeUserStore()
	companies := newCompanyTestStore()
	companyID := uuid.New()
	owner := seedCompanyUser(t, users, "owner-me@example.com", &companyID, 2)
	c := makeCompany(t, companies, owner.ID, "MyCo")
	c.ID = companyID
	companies.put(c)
	r, signer := buildCompanyRouter(t, users, companies)

	w := doJSON(t, r, http.MethodGet, "/v1/me/company", tokenForTier(t, signer, owner, 2), nil)
	require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())

	data := rawDataMap(t, w)
	assert.Equal(t, "MyCo", data["name"])
	// OWNER view: registrationNo IS present here (the caller's own data).
	assert.Equal(t, "REG-MyCo", data["registrationNo"])
	// owner_user_id stays excluded even in the owner view.
	_, present := data["ownerUserId"]
	assert.False(t, present, "owner view must still exclude ownerUserId")
}

func TestCompanyHandler_GetMyCompany_NoCompany(t *testing.T) {
	users := newFakeUserStore()
	companies := newCompanyTestStore()
	// A user with no company_id.
	lone := seedCompanyUser(t, users, "lone-me@example.com", nil, 2)
	r, signer := buildCompanyRouter(t, users, companies)

	w := doJSON(t, r, http.MethodGet, "/v1/me/company", tokenForTier(t, signer, lone, 2), nil)
	require.Equal(t, http.StatusNotFound, w.Code, "body: %s", w.Body.String())
	assert.Equal(t, "COMPANY_NOT_FOUND", errCode(t, w))
}

func TestCompanyHandler_GetMyCompany_Unauthenticated(t *testing.T) {
	users := newFakeUserStore()
	companies := newCompanyTestStore()
	r, _ := buildCompanyRouter(t, users, companies)

	w := doJSON(t, r, http.MethodGet, "/v1/me/company", "", nil)
	assert.Equal(t, http.StatusUnauthorized, w.Code, "body: %s", w.Body.String())
}

// --- Authed PUT /v1/me/company (owner-gated + RequireTier(1)) ---

func TestCompanyHandler_UpdateMyCompany_OwnerSuccess(t *testing.T) {
	users := newFakeUserStore()
	companies := newCompanyTestStore()
	companyID := uuid.New()
	owner := seedCompanyUser(t, users, "owner-put@example.com", &companyID, 1)
	c := makeCompany(t, companies, owner.ID, "PutCo")
	c.ID = companyID
	companies.put(c)
	r, signer := buildCompanyRouter(t, users, companies)

	w := doJSON(t, r, http.MethodPut, "/v1/me/company", tokenForTier(t, signer, owner, 1),
		map[string]any{"name": "PutCo Renamed", "handle": "putco"})
	require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())

	data := rawDataMap(t, w)
	assert.Equal(t, "PutCo Renamed", data["name"])
	assert.Equal(t, "putco", data["handle"])
	// 200 returns the PUBLIC projection (no registrationNo) per the frozen contract.
	_, present := data["registrationNo"]
	assert.False(t, present, "PUT response is CompanyProfile (public), no registrationNo")
}

func TestCompanyHandler_UpdateMyCompany_NonOwnerForbidden(t *testing.T) {
	users := newFakeUserStore()
	companies := newCompanyTestStore()
	companyID := uuid.New()
	owner := seedCompanyUser(t, users, "real-owner@example.com", &companyID, 1)
	c := makeCompany(t, companies, owner.ID, "GatedCo")
	c.ID = companyID
	companies.put(c)
	// A different member of the SAME company who is NOT the owner.
	member := seedCompanyUser(t, users, "member-put@example.com", &companyID, 1)
	r, signer := buildCompanyRouter(t, users, companies)

	w := doJSON(t, r, http.MethodPut, "/v1/me/company", tokenForTier(t, signer, member, 1),
		map[string]any{"name": "Hijacked"})
	require.Equal(t, http.StatusForbidden, w.Code, "body: %s", w.Body.String())
	assert.Equal(t, "NOT_COMPANY_OWNER", errCode(t, w))

	// The company name must be unchanged.
	stored, err := companies.GetByID(context.Background(), companyID)
	require.NoError(t, err)
	assert.Equal(t, "GatedCo", stored.Name)
}

func TestCompanyHandler_UpdateMyCompany_TierBlocked(t *testing.T) {
	users := newFakeUserStore()
	companies := newCompanyTestStore()
	companyID := uuid.New()
	owner := seedCompanyUser(t, users, "tier0-owner@example.com", &companyID, 0)
	c := makeCompany(t, companies, owner.ID, "TierCo")
	c.ID = companyID
	companies.put(c)
	r, signer := buildCompanyRouter(t, users, companies)

	// Tier-0 token: RequireTier(1) must reject before the handler runs.
	w := doJSON(t, r, http.MethodPut, "/v1/me/company", tokenForTier(t, signer, owner, 0),
		map[string]any{"name": "Should Not Apply"})
	require.Equal(t, http.StatusForbidden, w.Code, "body: %s", w.Body.String())
	assert.Equal(t, "KYC_TIER_REQUIRED", errCode(t, w))
}

func TestCompanyHandler_UpdateMyCompany_ValidationError(t *testing.T) {
	users := newFakeUserStore()
	companies := newCompanyTestStore()
	companyID := uuid.New()
	owner := seedCompanyUser(t, users, "validate-owner@example.com", &companyID, 1)
	c := makeCompany(t, companies, owner.ID, "ValCo")
	c.ID = companyID
	companies.put(c)
	r, signer := buildCompanyRouter(t, users, companies)

	// Missing required name → binding VALIDATION_ERROR.
	w := doJSON(t, r, http.MethodPut, "/v1/me/company", tokenForTier(t, signer, owner, 1),
		map[string]any{"handle": "valco"})
	require.Equal(t, http.StatusBadRequest, w.Code, "body: %s", w.Body.String())
	assert.Equal(t, "VALIDATION_ERROR", errCode(t, w))
}

func TestCompanyHandler_UpdateMyCompany_HandleTaken(t *testing.T) {
	users := newFakeUserStore()
	companies := newCompanyTestStore()
	companyID := uuid.New()
	owner := seedCompanyUser(t, users, "conflict-owner@example.com", &companyID, 1)
	c := makeCompany(t, companies, owner.ID, "ConflictCo")
	c.ID = companyID
	companies.put(c)
	// Inject a handle-taken error from the store (the partial-unique 23505 path).
	companies.updateErr = domain.ErrHandleTaken
	r, signer := buildCompanyRouter(t, users, companies)

	w := doJSON(t, r, http.MethodPut, "/v1/me/company", tokenForTier(t, signer, owner, 1),
		map[string]any{"name": "ConflictCo", "handle": "taken"})
	require.Equal(t, http.StatusConflict, w.Code, "body: %s", w.Body.String())
	assert.Equal(t, "HANDLE_TAKEN", errCode(t, w))
}

func TestCompanyHandler_UpdateMyCompany_IdentityFromClaims(t *testing.T) {
	users := newFakeUserStore()
	companies := newCompanyTestStore()
	companyID := uuid.New()
	owner := seedCompanyUser(t, users, "identity-owner@example.com", &companyID, 1)
	c := makeCompany(t, companies, owner.ID, "IdentityCo")
	c.ID = companyID
	companies.put(c)
	r, signer := buildCompanyRouter(t, users, companies)

	// A body-supplied id/ownerUserId must be IGNORED — the owner-gate uses claims.Subject.
	attacker := seedCompanyUser(t, users, "attacker@example.com", &companyID, 1)
	w := doJSON(t, r, http.MethodPut, "/v1/me/company", tokenForTier(t, signer, owner, 1),
		map[string]any{"name": "Renamed via claims", "id": attacker.ID.String(), "ownerUserId": attacker.ID.String()})
	require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())

	// The update applied to the OWNER's company (resolved from claims), not any body id.
	stored, err := companies.GetByID(context.Background(), companyID)
	require.NoError(t, err)
	assert.Equal(t, "Renamed via claims", stored.Name)
}
