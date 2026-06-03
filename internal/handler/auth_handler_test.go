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

func init() {
	gin.SetMode(gin.TestMode)
}

// --- Fake stores for unit tests ---

type fakeUserStore struct {
	users map[string]*domain.User
}

func newFakeUserStore() *fakeUserStore {
	return &fakeUserStore{users: make(map[string]*domain.User)}
}

func (f *fakeUserStore) Create(_ context.Context, u *domain.User) error {
	if _, exists := f.users[u.Email]; exists {
		return domain.ErrEmailTaken
	}

	f.users[u.Email] = u

	return nil
}

func (f *fakeUserStore) GetByID(_ context.Context, id uuid.UUID) (*domain.User, error) {
	for _, u := range f.users {
		if u.ID == id {
			return u, nil
		}
	}

	return nil, domain.ErrNotFound
}

func (f *fakeUserStore) GetByEmail(_ context.Context, email string) (*domain.User, error) {
	u, ok := f.users[email]
	if !ok {
		return nil, domain.ErrNotFound
	}

	return u, nil
}

func (f *fakeUserStore) UpdateProfile(_ context.Context, id uuid.UUID, displayName string, avatarURL *string) error {
	for _, u := range f.users {
		if u.ID == id {
			u.DisplayName = displayName
			u.AvatarURL = avatarURL

			return nil
		}
	}

	return domain.ErrNotFound
}

func (f *fakeUserStore) UpdateKYCTier(_ context.Context, id uuid.UUID, tier int16) error {
	for _, u := range f.users {
		if u.ID == id {
			u.KYCTier = tier

			return nil
		}
	}

	return domain.ErrNotFound
}

func (f *fakeUserStore) BumpTokenVersion(_ context.Context, id uuid.UUID) (int, error) {
	for _, u := range f.users {
		if u.ID == id {
			u.TokenVersion++

			return u.TokenVersion, nil
		}
	}

	return 0, domain.ErrNotFound
}

type fakeCompanyStore struct{}

func (f *fakeCompanyStore) Create(_ context.Context, _ *domain.Company) error { return nil }
func (f *fakeCompanyStore) GetByID(_ context.Context, _ uuid.UUID) (*domain.Company, error) {
	return nil, domain.ErrNotFound
}

type fakeRefreshTokenStore struct {
	tokens map[uuid.UUID]*domain.RefreshToken
}

func newFakeRefreshTokenStore() *fakeRefreshTokenStore {
	return &fakeRefreshTokenStore{tokens: make(map[uuid.UUID]*domain.RefreshToken)}
}

func (f *fakeRefreshTokenStore) Create(_ context.Context, rt *domain.RefreshToken) error {
	f.tokens[rt.ID] = rt
	return nil
}

func (f *fakeRefreshTokenStore) GetByID(_ context.Context, id uuid.UUID) (*domain.RefreshToken, error) {
	rt, ok := f.tokens[id]
	if !ok {
		return nil, domain.ErrInvalidRefresh
	}

	return rt, nil
}

func (f *fakeRefreshTokenStore) MarkUsed(_ context.Context, id uuid.UUID, now time.Time) error {
	if rt, ok := f.tokens[id]; ok {
		rt.UsedAt = &now
		rt.RevokedAt = &now
	}

	return nil
}

func (f *fakeRefreshTokenStore) RevokeFamily(_ context.Context, familyID uuid.UUID, now time.Time) error {
	for _, rt := range f.tokens {
		if rt.FamilyID == familyID && rt.RevokedAt == nil {
			t := now
			rt.RevokedAt = &t
		}
	}

	return nil
}

// --- Test helpers ---

func buildRouter(t *testing.T) (*gin.Engine, *jwt.Signer, *fakeUserStore) {
	t.Helper()

	signer, err := jwt.NewEphemeralSigner(10 * time.Minute)
	require.NoError(t, err)

	userStore := newFakeUserStore()
	companyStore := &fakeCompanyStore{}
	rtStore := newFakeRefreshTokenStore()

	// Pass nil Transactioner — fakeCompanyStore is non-atomic (acceptable for handler unit tests).
	authSvc := service.NewAuthService(userStore, companyStore, rtStore, nil, signer, 10*time.Minute, 24)
	profileSvc := service.NewProfileService(userStore)

	r := gin.New()
	r.Use(middleware.Recover())
	r.Use(middleware.RequestID())

	authH := handler.NewAuthHandler(authSvc, signer)
	auth := r.Group("/v1/auth")
	auth.POST("/register", authH.Register)
	auth.POST("/login", authH.Login)
	auth.POST("/refresh", authH.Refresh)
	auth.POST("/logout", middleware.Auth(signer), authH.Logout)

	meH := handler.NewMeHandler(profileSvc)
	profH := handler.NewProfileHandler(profileSvc)
	me := r.Group("/v1/me")
	me.Use(middleware.Auth(signer))
	me.GET("", meH.Get)
	me.GET("/profile", profH.Get)
	me.PUT("/profile", middleware.RequireTier(1), profH.Update)

	return r, signer, userStore
}

func postJSON(t *testing.T, r http.Handler, path string, body any) *httptest.ResponseRecorder {
	t.Helper()

	b, err := json.Marshal(body)
	require.NoError(t, err)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, path, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	return w
}

func getJSON(t *testing.T, r http.Handler, path, authHeader string) *httptest.ResponseRecorder {
	t.Helper()

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, path, http.NoBody)
	req.Header.Set("Authorization", authHeader)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	return w
}

// --- Tests ---

func TestRegister_HappyPath(t *testing.T) {
	r, _, _ := buildRouter(t)

	w := postJSON(t, r, "/v1/auth/register", map[string]any{
		"email":       "alice@example.com",
		"password":    "superSecurePassword123",
		"displayName": "Alice",
		"accountType": "PERSONAL",
	})

	assert.Equal(t, http.StatusCreated, w.Code)

	var resp map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))

	data := resp["data"].(map[string]any)
	user := data["user"].(map[string]any)
	assert.Equal(t, "alice@example.com", user["email"])
	assert.Equal(t, "PERSONAL", user["accountType"])
	assert.Equal(t, float64(0), user["kycTier"])
}

func TestRegister_EmailTaken(t *testing.T) {
	r, _, _ := buildRouter(t)

	body := map[string]any{
		"email":       "dup@example.com",
		"password":    "superSecurePassword123",
		"displayName": "Dup",
		"accountType": "PERSONAL",
	}

	postJSON(t, r, "/v1/auth/register", body)      // first
	w := postJSON(t, r, "/v1/auth/register", body) // duplicate

	assert.Equal(t, http.StatusConflict, w.Code)

	var resp map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	errBody := resp["error"].(map[string]any)
	assert.Equal(t, "EMAIL_TAKEN", errBody["code"])
}

func TestRegister_WeakPassword(t *testing.T) {
	r, _, _ := buildRouter(t)

	w := postJSON(t, r, "/v1/auth/register", map[string]any{
		"email":       "weak@example.com",
		"password":    "short",
		"displayName": "Weak",
		"accountType": "PERSONAL",
	})

	// Binding min=12 returns 400 VALIDATION_ERROR before we even reach service.
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRegister_MissingEmail(t *testing.T) {
	r, _, _ := buildRouter(t)

	w := postJSON(t, r, "/v1/auth/register", map[string]any{
		"password":    "superSecurePassword123",
		"displayName": "NoEmail",
		"accountType": "PERSONAL",
	})

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var resp map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	errBody := resp["error"].(map[string]any)
	assert.Equal(t, "VALIDATION_ERROR", errBody["code"])
}

func TestRegister_CompanyNameTooLong(t *testing.T) {
	r, _, _ := buildRouter(t)

	longName := ""
	for i := 0; i < 201; i++ {
		longName += "x"
	}

	w := postJSON(t, r, "/v1/auth/register", map[string]any{
		"email":       "biglongco@example.com",
		"password":    "superSecurePassword123",
		"displayName": "BigCo",
		"accountType": "COMPANY",
		"companyName": longName,
	})

	// Binding max=200 rejects with 400 VALIDATION_ERROR before the service runs.
	assert.Equal(t, http.StatusBadRequest, w.Code)

	var resp map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	errBody := resp["error"].(map[string]any)
	assert.Equal(t, "VALIDATION_ERROR", errBody["code"])
}

func TestLogin_HappyPath(t *testing.T) {
	r, _, _ := buildRouter(t)

	// Register first.
	postJSON(t, r, "/v1/auth/register", map[string]any{
		"email":       "bob@example.com",
		"password":    "superSecurePassword123",
		"displayName": "Bob",
		"accountType": "PERSONAL",
	})

	w := postJSON(t, r, "/v1/auth/login", map[string]any{
		"email":    "bob@example.com",
		"password": "superSecurePassword123",
	})

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	data := resp["data"].(map[string]any)
	assert.NotEmpty(t, data["accessToken"])
	assert.NotEmpty(t, data["refreshToken"])
	assert.Equal(t, "Bearer", data["tokenType"])
}

func TestLogin_WrongPassword(t *testing.T) {
	r, _, _ := buildRouter(t)

	postJSON(t, r, "/v1/auth/register", map[string]any{
		"email":       "carol@example.com",
		"password":    "superSecurePassword123",
		"displayName": "Carol",
		"accountType": "PERSONAL",
	})

	w := postJSON(t, r, "/v1/auth/login", map[string]any{
		"email":    "carol@example.com",
		"password": "wrongpassword",
	})

	assert.Equal(t, http.StatusUnauthorized, w.Code)

	var resp map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	errBody := resp["error"].(map[string]any)
	assert.Equal(t, "INVALID_CREDENTIALS", errBody["code"])
}

func TestLogin_UnknownEmail(t *testing.T) {
	r, _, _ := buildRouter(t)

	w := postJSON(t, r, "/v1/auth/login", map[string]any{
		"email":    "ghost@example.com",
		"password": "superSecurePassword123",
	})

	// Must be same error code as wrong password (no enumeration).
	assert.Equal(t, http.StatusUnauthorized, w.Code)

	var resp map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	errBody := resp["error"].(map[string]any)
	assert.Equal(t, "INVALID_CREDENTIALS", errBody["code"])
}

func TestRefresh_HappyPath(t *testing.T) {
	r, _, _ := buildRouter(t)

	postJSON(t, r, "/v1/auth/register", map[string]any{
		"email":       "dave@example.com",
		"password":    "superSecurePassword123",
		"displayName": "Dave",
		"accountType": "PERSONAL",
	})

	loginW := postJSON(t, r, "/v1/auth/login", map[string]any{
		"email":    "dave@example.com",
		"password": "superSecurePassword123",
	})

	var loginResp map[string]any
	require.NoError(t, json.Unmarshal(loginW.Body.Bytes(), &loginResp))
	loginData := loginResp["data"].(map[string]any)
	refreshToken := loginData["refreshToken"].(string)

	w := postJSON(t, r, "/v1/auth/refresh", map[string]any{
		"refreshToken": refreshToken,
	})

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	data := resp["data"].(map[string]any)
	assert.NotEmpty(t, data["accessToken"])
	assert.NotEmpty(t, data["refreshToken"])
	// New token must differ from old one.
	assert.NotEqual(t, refreshToken, data["refreshToken"])
}

func TestRefresh_ReuseDetected(t *testing.T) {
	r, _, _ := buildRouter(t)

	postJSON(t, r, "/v1/auth/register", map[string]any{
		"email":       "eve@example.com",
		"password":    "superSecurePassword123",
		"displayName": "Eve",
		"accountType": "PERSONAL",
	})

	loginW := postJSON(t, r, "/v1/auth/login", map[string]any{
		"email":    "eve@example.com",
		"password": "superSecurePassword123",
	})

	var loginResp map[string]any
	require.NoError(t, json.Unmarshal(loginW.Body.Bytes(), &loginResp))
	loginData := loginResp["data"].(map[string]any)
	refreshToken := loginData["refreshToken"].(string)

	// Use it once.
	postJSON(t, r, "/v1/auth/refresh", map[string]any{
		"refreshToken": refreshToken,
	})

	// Use same token again — reuse detection must trigger.
	w := postJSON(t, r, "/v1/auth/refresh", map[string]any{
		"refreshToken": refreshToken,
	})

	assert.Equal(t, http.StatusUnauthorized, w.Code)

	var resp map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	errBody := resp["error"].(map[string]any)
	assert.Equal(t, "REFRESH_REUSE_DETECTED", errBody["code"])
}

func TestRefresh_InvalidToken(t *testing.T) {
	r, _, _ := buildRouter(t)

	const fakeRefreshToken = "not-a-valid-token" //nolint:gosec // G101: test fixture string, not a real credential

	w := postJSON(t, r, "/v1/auth/refresh", map[string]any{
		"refreshToken": fakeRefreshToken,
	})

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestGetMe_HappyPath(t *testing.T) {
	r, signer, userStore := buildRouter(t)

	// Create user directly in store.
	now := time.Now().UTC()
	u := &domain.User{
		ID:          uuid.New(),
		Email:       "frank@example.com",
		DisplayName: "Frank",
		AccountType: "PERSONAL",
		KYCTier:     0,
		Status:      "ACTIVE",
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	require.NoError(t, userStore.Create(context.Background(), u))

	token, err := signer.Issue(u.ID.String(), u.AccountType, u.KYCTier, u.TokenVersion)
	require.NoError(t, err)

	w := getJSON(t, r, "/v1/me", "Bearer "+token)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	data := resp["data"].(map[string]any)
	assert.Equal(t, "frank@example.com", data["email"])
}

func TestGetMe_Unauthorized(t *testing.T) {
	r, _, _ := buildRouter(t)

	w := getJSON(t, r, "/v1/me", "")
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestGetMe_InvalidToken(t *testing.T) {
	r, _, _ := buildRouter(t)

	w := getJSON(t, r, "/v1/me", "Bearer not.a.jwt")
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}
