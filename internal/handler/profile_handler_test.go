package handler_test

import (
	"bytes"
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
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func strp(s string) *string { return &s }

// seedProfileUser inserts an ACTIVE user into the handler-test fakeUserStore.
func seedProfileUser(t *testing.T, store *fakeUserStore, mutate func(u *domain.User)) *domain.User {
	t.Helper()

	now := time.Now().UTC()
	u := &domain.User{
		ID:          uuid.New(),
		Email:       "profile-handler@example.com",
		DisplayName: "Profile User",
		AccountType: domain.AccountTypePersonal,
		Status:      domain.UserStatusActive,
		KYCTier:     1,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	if mutate != nil {
		mutate(u)
	}
	require.NoError(t, store.Create(context.Background(), u))

	return u
}

// buildProfileRouter wires a Gin engine that mirrors router.go for the profile
// surface: a PUBLIC /v1/users/:userId/profile group (no auth) and a PROTECTED
// /v1/me/profile group (Auth + RequireTier(1) on PUT), backed by one ProfileService
// over the shared fakeUserStore.
func buildProfileRouter(t *testing.T) (*gin.Engine, *jwt.Signer, *fakeUserStore) {
	t.Helper()

	signer, err := jwt.NewEphemeralSigner(10 * time.Minute)
	require.NoError(t, err)

	userStore := newFakeUserStore()
	profSvc := service.NewProfileService(userStore)

	r := gin.New()
	r.Use(middleware.Recover())

	// Public profile-by-id (no Auth) — matches router.go pub group.
	pub := r.Group("/v1/users")
	pubH := handler.NewPublicProfileHandler(profSvc)
	pub.GET("/:userId/profile", pubH.Get)

	// Protected own-profile group.
	me := r.Group("/v1/me")
	me.Use(middleware.Auth(signer))
	profH := handler.NewProfileHandler(profSvc)
	me.GET("/profile", profH.Get)
	me.PUT("/profile", middleware.RequireTier(1), profH.Update)

	return r, signer, userStore
}

func getJSON(t *testing.T, r http.Handler, path string) *httptest.ResponseRecorder {
	t.Helper()

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, path, nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	return w
}

// putMyProfile PUTs body to /v1/me/profile with a bearer token.
func putMyProfile(t *testing.T, r http.Handler, token string, body any) *httptest.ResponseRecorder {
	t.Helper()

	var buf bytes.Buffer
	require.NoError(t, json.NewEncoder(&buf).Encode(body))

	req := httptest.NewRequestWithContext(context.Background(), http.MethodPut, "/v1/me/profile", &buf)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	return w
}

// errCode pulls the {"error":{"code":...}} machine code out of a response body.
func errCode(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()

	var env struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &env), "body: %s", w.Body.String())

	return env.Error.Code
}

// rawDataMap unmarshals the {"data":{...}} envelope into a generic map so absence
// of a key (PII leak check) can be asserted directly.
func rawDataMap(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	t.Helper()

	var env struct {
		Data map[string]any `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &env), "body: %s", w.Body.String())

	return env.Data
}

// TestPublicProfileHandler_Get_PIISafe is the decisive PII-leak guard: the public
// endpoint MUST return EXACTLY the 12 allowlisted fields and MUST NOT expose any
// PII column even though the underlying domain.User carries them.
func TestPublicProfileHandler_Get_PIISafe(t *testing.T) {
	r, _, store := buildProfileRouter(t)

	u := seedProfileUser(t, store, func(u *domain.User) {
		u.Email = "secret@example.com"
		u.Handle = strp("publichandle")
		u.Headline = strp("Senior Engineer")
		u.Bio = strp("About me")
		u.Location = strp("Taipei")
		u.AvatarURL = strp("https://cdn.example.com/a.png")
		u.CoverURL = strp("https://cdn.example.com/c.png")
		u.KYCTier = 2
		u.LegalNameEnc = []byte("ciphertext-legal")
		u.NationalIDEnc = []byte("ciphertext-natid")
		u.EmailVerified = true
		u.TokenVersion = 7
		companyID := uuid.New()
		u.CompanyID = &companyID
	})

	w := getJSON(t, r, "/v1/users/"+u.ID.String()+"/profile")
	require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())

	data := rawDataMap(t, w)

	// EXACTLY the 12 PII-safe fields — no more.
	wantKeys := []string{
		"id", "handle", "displayName", "headline", "bio", "location",
		"avatarUrl", "coverUrl", "accountType", "verified", "kycTier", "joinedAt",
	}
	for _, k := range wantKeys {
		assert.Containsf(t, data, k, "public profile must include %q", k)
	}
	assert.Lenf(t, data, len(wantKeys), "public profile must contain EXACTLY %d fields, got %v", len(wantKeys), keysOf(data))

	// PII columns MUST be ABSENT (key not present at all, not merely empty).
	for _, leak := range []string{
		"email", "legalName", "legalNameEnc", "nationalId", "nationalIdEnc",
		"passwordHash", "status", "companyId", "emailVerified", "tokenVersion",
		"mfaEnabled", "updatedAt", "deletedAt",
	} {
		_, present := data[leak]
		assert.Falsef(t, present, "PII field %q MUST NOT appear in the public profile", leak)
	}

	// Derived / mapped values.
	assert.Equal(t, true, data["verified"], "verified must be derived from kycTier >= 1")
	assert.EqualValues(t, 2, data["kycTier"])
	assert.Equal(t, "publichandle", data["handle"])
	assert.NotEmpty(t, data["joinedAt"], "joinedAt must be set from created_at")
}

// TestPublicProfileHandler_Get_VerifiedFalseBelowTier1 confirms verified=false for
// a tier-0 account.
func TestPublicProfileHandler_Get_VerifiedFalseBelowTier1(t *testing.T) {
	r, _, store := buildProfileRouter(t)
	u := seedProfileUser(t, store, func(u *domain.User) { u.KYCTier = 0 })

	w := getJSON(t, r, "/v1/users/"+u.ID.String()+"/profile")
	require.Equal(t, http.StatusOK, w.Code)

	data := rawDataMap(t, w)
	assert.Equal(t, false, data["verified"], "tier-0 account must not be verified")
}

func TestPublicProfileHandler_Get_BadUUID(t *testing.T) {
	r, _, _ := buildProfileRouter(t)

	w := getJSON(t, r, "/v1/users/not-a-uuid/profile")
	require.Equal(t, http.StatusBadRequest, w.Code, "body: %s", w.Body.String())
	assert.Equal(t, "INVALID_USER_ID", errCode(t, w))
}

func TestPublicProfileHandler_Get_NotFound(t *testing.T) {
	r, _, _ := buildProfileRouter(t)

	w := getJSON(t, r, "/v1/users/"+uuid.New().String()+"/profile")
	require.Equal(t, http.StatusNotFound, w.Code, "body: %s", w.Body.String())
	assert.Equal(t, "USER_NOT_FOUND", errCode(t, w))
}

// TestProfileHandler_GetOwn_IncludesEmail confirms the authed own view returns the
// 12 public fields PLUS email (own data, not a leak) — and still no other PII.
func TestProfileHandler_GetOwn_IncludesEmail(t *testing.T) {
	r, signer, store := buildProfileRouter(t)
	u := seedProfileUser(t, store, func(u *domain.User) {
		u.Email = "owner@example.com"
		u.LegalNameEnc = []byte("ciphertext")
	})

	token, err := signer.Issue(u.ID.String(), domain.AccountTypePersonal, u.KYCTier, 0, true)
	require.NoError(t, err)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/v1/me/profile", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())
	data := rawDataMap(t, w)

	assert.Equal(t, "owner@example.com", data["email"], "own profile must include the caller's own email")
	for _, leak := range []string{"legalName", "legalNameEnc", "nationalId", "passwordHash", "tokenVersion"} {
		_, present := data[leak]
		assert.Falsef(t, present, "own profile must not leak %q", leak)
	}
}

func TestProfileHandler_GetOwn_Unauthenticated(t *testing.T) {
	r, _, _ := buildProfileRouter(t)

	w := getJSON(t, r, "/v1/me/profile")
	assert.Equal(t, http.StatusUnauthorized, w.Code, "body: %s", w.Body.String())
}

// TestProfileHandler_Update_Success exercises the full-replace PUT with the new
// public fields and asserts the response reflects the normalized values.
func TestProfileHandler_Update_Success(t *testing.T) {
	r, signer, store := buildProfileRouter(t)
	u := seedProfileUser(t, store, nil)

	token, err := signer.Issue(u.ID.String(), domain.AccountTypePersonal, u.KYCTier, 0, true)
	require.NoError(t, err)

	w := putMyProfile(t, r, token, handler.UpdateProfileRequest{
		DisplayName: "Updated Name",
		Handle:      strp("New_Handle"),
		Headline:    strp("Staff Engineer"),
		Bio:         strp("hello"),
		Location:    strp("Tokyo"),
		AvatarURL:   strp("https://cdn.example.com/new.png"),
		CoverURL:    strp("https://cdn.example.com/cover.png"),
	})
	require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())

	data := rawDataMap(t, w)
	assert.Equal(t, "Updated Name", data["displayName"])
	assert.Equal(t, "new_handle", data["handle"], "handle must be lowercased server-side")
	assert.Equal(t, "Staff Engineer", data["headline"])
	assert.Equal(t, "Tokyo", data["location"])
}

func TestProfileHandler_Update_BelowTier1Forbidden(t *testing.T) {
	r, signer, store := buildProfileRouter(t)
	u := seedProfileUser(t, store, func(u *domain.User) { u.KYCTier = 0 })

	// Token carries kycTier=0 → RequireTier(1) must reject before the handler runs.
	token, err := signer.Issue(u.ID.String(), domain.AccountTypePersonal, 0, 0, true)
	require.NoError(t, err)

	w := putMyProfile(t, r, token, handler.UpdateProfileRequest{DisplayName: "x"})
	require.Equal(t, http.StatusForbidden, w.Code, "body: %s", w.Body.String())
	assert.Equal(t, "KYC_TIER_REQUIRED", errCode(t, w))
}

func TestProfileHandler_Update_HandleTakenConflict(t *testing.T) {
	r, signer, store := buildProfileRouter(t)

	// User A already owns "taken".
	a := seedProfileUser(t, store, func(u *domain.User) {
		u.Email = "a@example.com"
		u.Handle = strp("taken")
	})
	_ = a

	// User B attempts to claim it (different case).
	b := seedProfileUser(t, store, func(u *domain.User) { u.Email = "b@example.com" })
	token, err := signer.Issue(b.ID.String(), domain.AccountTypePersonal, b.KYCTier, 0, true)
	require.NoError(t, err)

	w := putMyProfile(t, r, token, handler.UpdateProfileRequest{
		DisplayName: "B",
		Handle:      strp("TAKEN"),
	})
	require.Equal(t, http.StatusConflict, w.Code, "body: %s", w.Body.String())
	assert.Equal(t, "HANDLE_TAKEN", errCode(t, w))
}

func TestProfileHandler_Update_InvalidHandleValidationError(t *testing.T) {
	r, signer, store := buildProfileRouter(t)
	u := seedProfileUser(t, store, nil)

	token, err := signer.Issue(u.ID.String(), domain.AccountTypePersonal, u.KYCTier, 0, true)
	require.NoError(t, err)

	w := putMyProfile(t, r, token, handler.UpdateProfileRequest{
		DisplayName: "Valid",
		Handle:      strp("bad handle!"), // space + illegal char
	})
	require.Equal(t, http.StatusBadRequest, w.Code, "body: %s", w.Body.String())
	assert.Equal(t, "VALIDATION_ERROR", errCode(t, w))
}

func keysOf(m map[string]any) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}

	return ks
}
