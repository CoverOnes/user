package handler_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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

// fakeSavedStore is an in-memory SavedItemStore for SavedHandler tests. The list
// payloads + per-method errors are injectable so handler-level envelope shaping and
// error mapping can be asserted without a real DB. The JOIN / 23505 SQL semantics are
// covered by the Postgres integration test.
type fakeSavedStore struct {
	jobRefs   []domain.SavedItem
	companies []store.SavedCompanyRow

	createErr error
	deleteErr error
	listErr   error
	countErr  error

	// countRet is what CountByUserAndType returns (zero value 0 keeps existing
	// save-path tests well under the per-user-per-type cap).
	countRet int

	created   *domain.SavedItem
	deleteRet bool

	lastDeletedUser uuid.UUID
	lastDeletedType string
	lastDeletedID   uuid.UUID
}

func (f *fakeSavedStore) Create(_ context.Context, s *domain.SavedItem) error {
	if f.createErr != nil {
		return f.createErr
	}

	cp := *s
	f.created = &cp

	return nil
}

func (f *fakeSavedStore) DeleteByUserAndItem(_ context.Context, userID uuid.UUID, itemType string, itemID uuid.UUID) (bool, error) {
	if f.deleteErr != nil {
		return false, f.deleteErr
	}

	f.lastDeletedUser = userID
	f.lastDeletedType = itemType
	f.lastDeletedID = itemID

	return f.deleteRet, nil
}

func (f *fakeSavedStore) CountByUserAndType(_ context.Context, _ uuid.UUID, _ string) (int, error) {
	if f.countErr != nil {
		return 0, f.countErr
	}

	return f.countRet, nil
}

func (f *fakeSavedStore) ListJobRefs(_ context.Context, _ uuid.UUID) ([]domain.SavedItem, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}

	return f.jobRefs, nil
}

func (f *fakeSavedStore) ListCompaniesForUser(_ context.Context, _ uuid.UUID) ([]store.SavedCompanyRow, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}

	return f.companies, nil
}

// buildSavedRouter wires a Gin engine for the /v1/me/saved surface backed by a real
// SavedService over the supplied fakes (mirrors router.go: Auth on the me group, no
// RequireTier). The company-target existence check uses the supplied companyTestStore.
func buildSavedRouter(t *testing.T, companies *companyTestStore, saved store.SavedItemStore) (*gin.Engine, *jwt.Signer) {
	t.Helper()

	signer, err := jwt.NewEphemeralSigner(10 * time.Minute)
	require.NoError(t, err)

	svc := service.NewSavedService(companies, saved)
	savedH := handler.NewSavedHandler(svc)

	r := gin.New()
	r.Use(middleware.Recover())

	me := r.Group("/v1/me")
	me.Use(middleware.Auth(signer))

	group := me.Group("/saved")
	group.GET("", savedH.List)
	group.POST("", savedH.Save)
	group.DELETE("", savedH.Unsave)

	return r, signer
}

// dataItems unmarshals the {"data":{"items":[...]}} list envelope into generic maps so
// absence of a key (PII leak check) and field values can be asserted directly.
func dataItems(t *testing.T, w *httptest.ResponseRecorder) []map[string]any {
	t.Helper()

	var env struct {
		Data struct {
			Items []map[string]any `json:"items"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &env), "body: %s", w.Body.String())

	return env.Data.Items
}

func TestSavedHandler_List_Jobs_BareRefs(t *testing.T) {
	users := newFakeUserStore()
	me := seedConnHandlerUser(t, users, "me-saved-jobs@example.com")
	saved := &fakeSavedStore{
		jobRefs: []domain.SavedItem{
			{ID: uuid.New(), UserID: me.ID, ItemType: domain.SavedItemTypeJob, ItemID: uuid.New(), CreatedAt: time.Now().UTC()},
		},
	}
	r, signer := buildSavedRouter(t, newCompanyTestStore(), saved)

	w := doJSON(t, r, http.MethodGet, "/v1/me/saved?type=job", tokenFor(t, signer, me), nil)
	require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())

	items := dataItems(t, w)
	require.Len(t, items, 1)
	item := items[0]
	assert.Equal(t, "job", item["itemType"])
	assert.NotEmpty(t, item["savedId"])
	assert.NotEmpty(t, item["itemId"])
	assert.NotEmpty(t, item["savedAt"])
	// A bare job ref MUST NOT carry a hydrated company object.
	_, hasCompany := item["company"]
	assert.False(t, hasCompany, "a saved job ref must not carry a company projection")
}

func TestSavedHandler_List_Companies_PIISafe(t *testing.T) {
	users := newFakeUserStore()
	me := seedConnHandlerUser(t, users, "me-saved-co@example.com")
	saved := &fakeSavedStore{
		companies: []store.SavedCompanyRow{
			{
				SavedID:     uuid.New(),
				SavedAt:     time.Now().UTC(),
				CompanyID:   uuid.New(),
				Handle:      strp("acme"),
				Name:        "Acme Inc",
				Tagline:     strp("We build"),
				Location:    strp("Taipei"),
				Industry:    strp("SaaS"),
				CompanySize: strp("11-50"),
				LogoURL:     strp("https://cdn.example.com/acme.png"),
			},
		},
	}
	r, signer := buildSavedRouter(t, newCompanyTestStore(), saved)

	w := doJSON(t, r, http.MethodGet, "/v1/me/saved?type=company", tokenFor(t, signer, me), nil)
	require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())

	items := dataItems(t, w)
	require.Len(t, items, 1)
	item := items[0]
	assert.Equal(t, "company", item["itemType"])
	assert.NotEmpty(t, item["savedId"])

	company, ok := item["company"].(map[string]any)
	require.True(t, ok, "company object must be present")
	assert.Equal(t, "Acme Inc", company["name"])
	assert.Equal(t, "SaaS", company["industry"])

	// PII-safe: a saved-company card MUST NOT carry registration_no / owner_user_id / status.
	for _, leak := range []string{"registrationNo", "ownerUserId", "status", "createdAt"} {
		_, present := company[leak]
		assert.Falsef(t, present, "saved company card must not leak %q", leak)
	}
}

func TestSavedHandler_List_EmptyArrayNotNull(t *testing.T) {
	users := newFakeUserStore()
	me := seedConnHandlerUser(t, users, "me-saved-empty@example.com")
	saved := &fakeSavedStore{} // no rows
	r, signer := buildSavedRouter(t, newCompanyTestStore(), saved)

	w := doJSON(t, r, http.MethodGet, "/v1/me/saved?type=job", tokenFor(t, signer, me), nil)
	require.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), `"items":[]`, "empty list must serialize as [] not null")
}

func TestSavedHandler_List_MissingType(t *testing.T) {
	users := newFakeUserStore()
	me := seedConnHandlerUser(t, users, "me-saved-notype@example.com")
	r, signer := buildSavedRouter(t, newCompanyTestStore(), &fakeSavedStore{})

	w := doJSON(t, r, http.MethodGet, "/v1/me/saved", tokenFor(t, signer, me), nil)
	require.Equal(t, http.StatusBadRequest, w.Code, "body: %s", w.Body.String())
	assert.Equal(t, "VALIDATION_ERROR", errCode(t, w))
}

func TestSavedHandler_List_BadType(t *testing.T) {
	users := newFakeUserStore()
	me := seedConnHandlerUser(t, users, "me-saved-badtype@example.com")
	r, signer := buildSavedRouter(t, newCompanyTestStore(), &fakeSavedStore{})

	w := doJSON(t, r, http.MethodGet, "/v1/me/saved?type=person", tokenFor(t, signer, me), nil)
	require.Equal(t, http.StatusBadRequest, w.Code, "body: %s", w.Body.String())
	assert.Equal(t, "VALIDATION_ERROR", errCode(t, w))
}

func TestSavedHandler_List_Unauthenticated(t *testing.T) {
	r, _ := buildSavedRouter(t, newCompanyTestStore(), &fakeSavedStore{})

	w := doJSON(t, r, http.MethodGet, "/v1/me/saved?type=job", "", nil)
	assert.Equal(t, http.StatusUnauthorized, w.Code, "body: %s", w.Body.String())
}

func TestSavedHandler_Save_Job_Created(t *testing.T) {
	users := newFakeUserStore()
	me := seedConnHandlerUser(t, users, "saver-job@example.com")
	saved := &fakeSavedStore{}
	r, signer := buildSavedRouter(t, newCompanyTestStore(), saved)

	jobID := uuid.New()
	w := doJSON(t, r, http.MethodPost, "/v1/me/saved", tokenFor(t, signer, me),
		map[string]string{"itemType": "job", "itemId": jobID.String()})
	require.Equal(t, http.StatusCreated, w.Code, "body: %s", w.Body.String())

	data := rawDataMap(t, w)
	assert.Equal(t, "job", data["itemType"])
	assert.Equal(t, jobID.String(), data["itemId"])
	assert.NotEmpty(t, data["savedId"])
	assert.NotEmpty(t, data["savedAt"])

	// Identity-from-claims: the persisted owner MUST be the JWT subject, not a body value.
	require.NotNil(t, saved.created)
	assert.Equal(t, me.ID, saved.created.UserID, "bookmark owner must come from the token, not the body")
	assert.Equal(t, jobID, saved.created.ItemID)
}

func TestSavedHandler_Save_Company_Created(t *testing.T) {
	users := newFakeUserStore()
	me := seedConnHandlerUser(t, users, "saver-co@example.com")
	companies := newCompanyTestStore()
	company := makeCompany(t, companies, uuid.New(), "AcmeSaveCo")
	saved := &fakeSavedStore{}
	r, signer := buildSavedRouter(t, companies, saved)

	w := doJSON(t, r, http.MethodPost, "/v1/me/saved", tokenFor(t, signer, me),
		map[string]string{"itemType": "company", "itemId": company.ID.String()})
	require.Equal(t, http.StatusCreated, w.Code, "body: %s", w.Body.String())

	data := rawDataMap(t, w)
	assert.Equal(t, "company", data["itemType"])
	assert.Equal(t, company.ID.String(), data["itemId"])
}

func TestSavedHandler_Save_Company_TargetNotFound(t *testing.T) {
	users := newFakeUserStore()
	me := seedConnHandlerUser(t, users, "saver-co404@example.com")
	saved := &fakeSavedStore{}
	r, signer := buildSavedRouter(t, newCompanyTestStore(), saved)

	w := doJSON(t, r, http.MethodPost, "/v1/me/saved", tokenFor(t, signer, me),
		map[string]string{"itemType": "company", "itemId": uuid.New().String()})
	require.Equal(t, http.StatusNotFound, w.Code, "body: %s", w.Body.String())
	assert.Equal(t, "SAVED_TARGET_NOT_FOUND", errCode(t, w))
	assert.Nil(t, saved.created, "an absent company target must not create a bookmark")
}

func TestSavedHandler_Save_DuplicateConflict(t *testing.T) {
	users := newFakeUserStore()
	me := seedConnHandlerUser(t, users, "saver-dup@example.com")
	saved := &fakeSavedStore{createErr: domain.ErrSavedItemExists}
	r, signer := buildSavedRouter(t, newCompanyTestStore(), saved)

	w := doJSON(t, r, http.MethodPost, "/v1/me/saved", tokenFor(t, signer, me),
		map[string]string{"itemType": "job", "itemId": uuid.New().String()})
	require.Equal(t, http.StatusConflict, w.Code, "body: %s", w.Body.String())
	assert.Equal(t, "SAVED_ITEM_EXISTS", errCode(t, w))
}

func TestSavedHandler_Save_BadType(t *testing.T) {
	users := newFakeUserStore()
	me := seedConnHandlerUser(t, users, "saver-badtype@example.com")
	saved := &fakeSavedStore{}
	r, signer := buildSavedRouter(t, newCompanyTestStore(), saved)

	w := doJSON(t, r, http.MethodPost, "/v1/me/saved", tokenFor(t, signer, me),
		map[string]string{"itemType": "person", "itemId": uuid.New().String()})
	require.Equal(t, http.StatusBadRequest, w.Code, "body: %s", w.Body.String())
	assert.Equal(t, "VALIDATION_ERROR", errCode(t, w))
	assert.Nil(t, saved.created)
}

func TestSavedHandler_Save_BadUUID(t *testing.T) {
	users := newFakeUserStore()
	me := seedConnHandlerUser(t, users, "saver-baduuid@example.com")
	saved := &fakeSavedStore{}
	r, signer := buildSavedRouter(t, newCompanyTestStore(), saved)

	w := doJSON(t, r, http.MethodPost, "/v1/me/saved", tokenFor(t, signer, me),
		map[string]string{"itemType": "job", "itemId": "not-a-uuid"})
	require.Equal(t, http.StatusBadRequest, w.Code, "body: %s", w.Body.String())
	assert.Equal(t, "VALIDATION_ERROR", errCode(t, w))
	assert.Nil(t, saved.created)
}

func TestSavedHandler_Save_MissingFields(t *testing.T) {
	users := newFakeUserStore()
	me := seedConnHandlerUser(t, users, "saver-missing@example.com")
	saved := &fakeSavedStore{}
	r, signer := buildSavedRouter(t, newCompanyTestStore(), saved)

	// itemId missing → binding:"required" fails.
	w := doJSON(t, r, http.MethodPost, "/v1/me/saved", tokenFor(t, signer, me),
		map[string]string{"itemType": "job"})
	require.Equal(t, http.StatusBadRequest, w.Code, "body: %s", w.Body.String())
	assert.Equal(t, "VALIDATION_ERROR", errCode(t, w))
}

func TestSavedHandler_Save_Unauthenticated(t *testing.T) {
	r, _ := buildSavedRouter(t, newCompanyTestStore(), &fakeSavedStore{})

	w := doJSON(t, r, http.MethodPost, "/v1/me/saved", "",
		map[string]string{"itemType": "job", "itemId": uuid.New().String()})
	assert.Equal(t, http.StatusUnauthorized, w.Code, "body: %s", w.Body.String())
}

func TestSavedHandler_Unsave_Removed(t *testing.T) {
	users := newFakeUserStore()
	me := seedConnHandlerUser(t, users, "unsaver@example.com")
	saved := &fakeSavedStore{deleteRet: true}
	r, signer := buildSavedRouter(t, newCompanyTestStore(), saved)

	itemID := uuid.New()
	w := doJSON(t, r, http.MethodDelete, "/v1/me/saved?type=job&itemId="+itemID.String(), tokenFor(t, signer, me), nil)
	require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())

	data := rawDataMap(t, w)
	assert.Equal(t, "job", data["itemType"])
	assert.Equal(t, itemID.String(), data["itemId"])
	assert.Equal(t, true, data["removed"])

	// Identity-scoped: the delete MUST be keyed to the JWT subject.
	assert.Equal(t, me.ID, saved.lastDeletedUser, "unsave must scope to the caller's id")
	assert.Equal(t, itemID, saved.lastDeletedID)
}

func TestSavedHandler_Unsave_Idempotent(t *testing.T) {
	users := newFakeUserStore()
	me := seedConnHandlerUser(t, users, "unsaver-idem@example.com")
	saved := &fakeSavedStore{deleteRet: false} // absent bookmark
	r, signer := buildSavedRouter(t, newCompanyTestStore(), saved)

	w := doJSON(t, r, http.MethodDelete, "/v1/me/saved?type=company&itemId="+uuid.New().String(), tokenFor(t, signer, me), nil)
	// Double-unsave must be 200 {removed:false}, NOT 404 (resolved-decision #2).
	require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())

	data := rawDataMap(t, w)
	assert.Equal(t, false, data["removed"], "unsaving an absent bookmark must return removed:false, not 404")
}

func TestSavedHandler_Unsave_BadType(t *testing.T) {
	users := newFakeUserStore()
	me := seedConnHandlerUser(t, users, "unsaver-badtype@example.com")
	r, signer := buildSavedRouter(t, newCompanyTestStore(), &fakeSavedStore{})

	w := doJSON(t, r, http.MethodDelete, "/v1/me/saved?type=person&itemId="+uuid.New().String(), tokenFor(t, signer, me), nil)
	require.Equal(t, http.StatusBadRequest, w.Code, "body: %s", w.Body.String())
	assert.Equal(t, "VALIDATION_ERROR", errCode(t, w))
}

func TestSavedHandler_Unsave_BadUUID(t *testing.T) {
	users := newFakeUserStore()
	me := seedConnHandlerUser(t, users, "unsaver-baduuid@example.com")
	r, signer := buildSavedRouter(t, newCompanyTestStore(), &fakeSavedStore{})

	w := doJSON(t, r, http.MethodDelete, "/v1/me/saved?type=job&itemId=not-a-uuid", tokenFor(t, signer, me), nil)
	require.Equal(t, http.StatusBadRequest, w.Code, "body: %s", w.Body.String())
	assert.Equal(t, "VALIDATION_ERROR", errCode(t, w))
}

func TestSavedHandler_Unsave_Unauthenticated(t *testing.T) {
	r, _ := buildSavedRouter(t, newCompanyTestStore(), &fakeSavedStore{})

	w := doJSON(t, r, http.MethodDelete, "/v1/me/saved?type=job&itemId="+uuid.New().String(), "", nil)
	assert.Equal(t, http.StatusUnauthorized, w.Code, "body: %s", w.Body.String())
}
