package handler_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
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

func init() {
	gin.SetMode(gin.TestMode)
}

// validTWID is a checksum-valid Taiwan national ID for register fixtures
// (canonical example, NOT a real person's ID).
const validTWID = "A123456789"

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

func (f *fakeUserStore) UpdateProfile(_ context.Context, id uuid.UUID, in store.ProfileUpdate) error {
	// Mirror the Postgres partial-unique index: a non-nil handle already held by a
	// DIFFERENT live user yields ErrHandleTaken (case-insensitive).
	if in.Handle != nil {
		for _, other := range f.users {
			if other.ID != id && other.Handle != nil && strings.EqualFold(*other.Handle, *in.Handle) {
				return domain.ErrHandleTaken
			}
		}
	}

	for _, u := range f.users {
		if u.ID != id {
			continue
		}

		u.DisplayName = in.DisplayName
		u.Handle = in.Handle
		u.Headline = in.Headline
		u.Bio = in.Bio
		u.Location = in.Location
		u.AvatarURL = in.AvatarURL
		u.CoverURL = in.CoverURL

		return nil
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

func (f *fakeUserStore) SetEmailVerified(_ context.Context, id uuid.UUID) error {
	for _, u := range f.users {
		if u.ID == id {
			u.EmailVerified = true
			if u.KYCTier < 1 {
				u.KYCTier = 1
			}

			return nil
		}
	}

	return domain.ErrNotFound
}

func (f *fakeUserStore) SetPendingTOTPSecret(_ context.Context, id uuid.UUID, secretEnc []byte) error {
	for _, u := range f.users {
		if u.ID == id {
			u.TOTPSecretEnc = secretEnc

			return nil
		}
	}

	return domain.ErrNotFound
}

func (f *fakeUserStore) EnableMFA(_ context.Context, id uuid.UUID, backupCodesEnc []byte, enrolledAt time.Time) error {
	for _, u := range f.users {
		if u.ID != id {
			continue
		}

		// Mirror the service-layer fake CAS guard (fakes_test.go:163): reject a
		// second EnableMFA on an already-enabled row so the handler-layer fake
		// matches the real Postgres store's conditional UPDATE (mfa_enabled = false).
		if u.MFAEnabled {
			return domain.ErrMFAAlreadyEnabled
		}

		u.MFAEnabled = true
		u.MFABackupCodesEnc = backupCodesEnc
		u.MFAEnrolledAt = &enrolledAt

		return nil
	}

	return domain.ErrNotFound
}

func (f *fakeUserStore) DisableMFA(_ context.Context, id uuid.UUID) error {
	for _, u := range f.users {
		if u.ID != id {
			continue
		}
		u.MFAEnabled = false
		u.TOTPSecretEnc = nil
		u.MFABackupCodesEnc = nil
		u.MFAEnrolledAt = nil

		return nil
	}

	return domain.ErrNotFound
}

func (f *fakeUserStore) SetMFABackupCodes(_ context.Context, id uuid.UUID, backupCodesEnc []byte) error {
	for _, u := range f.users {
		if u.ID == id {
			u.MFABackupCodesEnc = backupCodesEnc

			return nil
		}
	}

	return domain.ErrNotFound
}

func (f *fakeUserStore) SetPasswordHash(_ context.Context, id uuid.UUID, hash string) error {
	for _, u := range f.users {
		if u.ID == id {
			u.PasswordHash = &hash

			return nil
		}
	}

	return domain.ErrNotFound
}

type fakeCompanyStore struct{}

func (f *fakeCompanyStore) Create(_ context.Context, _ *domain.Company) error { return nil }
func (f *fakeCompanyStore) GetByID(_ context.Context, _ uuid.UUID) (*domain.Company, error) {
	return nil, domain.ErrNotFound
}

func (f *fakeCompanyStore) Update(_ context.Context, _ uuid.UUID, _ *store.CompanyUpdate) error {
	return domain.ErrCompanyNotFound
}

func (f *fakeCompanyStore) ListMembers(_ context.Context, _ uuid.UUID) ([]store.CompanyMember, error) {
	return nil, nil
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

func (f *fakeRefreshTokenStore) MarkUsed(_ context.Context, id uuid.UUID, now time.Time) (bool, error) {
	rt, ok := f.tokens[id]
	if !ok {
		return false, nil
	}

	// CAS: only flip when used_at IS NULL AND revoked_at IS NULL.
	if rt.UsedAt != nil || rt.RevokedAt != nil {
		return false, nil
	}

	rt.UsedAt = &now
	rt.RevokedAt = &now

	return true, nil
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

	// cookieDomain="" (dev posture: omit Domain attr) + refreshTTLHours=24 (matches
	// the AuthService TTL above) so the cookie MaxAge is computed exactly as in prod.
	authH := handler.NewAuthHandler(authSvc, signer, "", 24)
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

// refreshCookieName mirrors the handler-internal cookie name (which is unexported).
// Tests live in package handler_test, so the constant cannot be imported directly.
const refreshCookieName = "refresh_token"

// findRefreshCookie returns the refresh_token cookie from a response recorder, or
// nil if absent. It parses the Set-Cookie headers via the standard library so
// attributes (HttpOnly/Secure/SameSite/Path/MaxAge) are populated for assertions.
func findRefreshCookie(w *httptest.ResponseRecorder) *http.Cookie {
	resp := http.Response{Header: w.Header()}
	for _, ck := range resp.Cookies() {
		if ck.Name == refreshCookieName {
			return ck
		}
	}

	return nil
}

// refreshTokenFromLogin performs login and returns the recorder plus the refresh
// token value. The token now lives only in the Set-Cookie header, never the body.
func refreshTokenFromLogin(t *testing.T, r http.Handler, email, password string) (w *httptest.ResponseRecorder, refreshToken string) {
	t.Helper()

	w = postJSON(t, r, "/v1/auth/login", map[string]any{
		"email":    email,
		"password": password,
	})
	require.Equal(t, http.StatusOK, w.Code)

	ck := findRefreshCookie(w)
	require.NotNil(t, ck, "login must set the refresh_token cookie")

	return w, ck.Value
}

// postRefreshCookie issues POST /v1/auth/refresh with the refresh token supplied via
// the HttpOnly cookie (the only supported transport) and an empty JSON body.
func postRefreshCookie(t *testing.T, r http.Handler, refreshToken string) *httptest.ResponseRecorder {
	t.Helper()

	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/auth/refresh", http.NoBody)
	if refreshToken != "" {
		req.AddCookie(&http.Cookie{Name: refreshCookieName, Value: refreshToken})
	}

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	return w
}

// getMe issues an authenticated GET against /v1/me (the only path these handler
// tests exercise via this helper). authHeader is the full Authorization value
// ("Bearer <token>", or "" to omit it).
func getMe(t *testing.T, r http.Handler, authHeader string) *httptest.ResponseRecorder {
	t.Helper()

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/v1/me", http.NoBody)
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}

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
		"legalName":   "Alice Wang",
		"nationalId":  validTWID,
	})

	assert.Equal(t, http.StatusCreated, w.Code)

	var resp map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))

	data := resp["data"].(map[string]any)
	user := data["user"].(map[string]any)
	assert.Equal(t, "alice@example.com", user["email"])
	assert.Equal(t, "PERSONAL", user["accountType"])
	assert.Equal(t, float64(0), user["kycTier"])
	// New register contract: PENDING_VERIFICATION + emailVerified=false, no tokens.
	assert.Equal(t, "PENDING_VERIFICATION", user["status"])
	assert.Equal(t, false, user["emailVerified"])
	_, hasAccess := data["accessToken"]
	assert.False(t, hasAccess, "register must not return an access token")
}

func TestRegister_EmailTaken(t *testing.T) {
	r, _, _ := buildRouter(t)

	body := map[string]any{
		"email":       "dup@example.com",
		"password":    "superSecurePassword123",
		"displayName": "Dup",
		"accountType": "PERSONAL",
		"legalName":   "Dup Wang",
		"nationalId":  validTWID,
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
		"legalName":   "Weak Wang",
		"nationalId":  validTWID,
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
		"legalName":   "Big Co Owner",
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
		"legalName":   "Bob Wang",
		"nationalId":  validTWID,
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
	assert.Equal(t, "Bearer", data["tokenType"])
	// The refresh token MUST NOT appear in the body anymore.
	_, present := data["refreshToken"]
	assert.False(t, present, "refreshToken must not be in the login response body")

	// It MUST be delivered as a hardened HttpOnly cookie instead.
	ck := findRefreshCookie(w)
	require.NotNil(t, ck, "login must set the refresh_token cookie")
	assert.NotEmpty(t, ck.Value, "refresh cookie must carry the token")
	assert.True(t, ck.HttpOnly, "refresh cookie must be HttpOnly")
	assert.True(t, ck.Secure, "refresh cookie must be Secure")
	assert.Equal(t, http.SameSiteStrictMode, ck.SameSite, "refresh cookie must be SameSite=Strict")
	assert.Equal(t, "/v1/auth", ck.Path, "refresh cookie must be path-scoped to /v1/auth")
	assert.Equal(t, 24*3600, ck.MaxAge, "refresh cookie MaxAge must be refreshTTLHours*3600")
	assert.Empty(t, ck.Domain, "dev posture: no Domain attribute")
}

func TestLogin_WrongPassword(t *testing.T) {
	r, _, _ := buildRouter(t)

	postJSON(t, r, "/v1/auth/register", map[string]any{
		"email":       "carol@example.com",
		"password":    "superSecurePassword123",
		"displayName": "Carol",
		"accountType": "PERSONAL",
		"legalName":   "Carol Wang",
		"nationalId":  validTWID,
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
		"legalName":   "Dave Wang",
		"nationalId":  validTWID,
	})

	_, refreshToken := refreshTokenFromLogin(t, r, "dave@example.com", "superSecurePassword123")

	w := postRefreshCookie(t, r, refreshToken)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	data := resp["data"].(map[string]any)
	assert.NotEmpty(t, data["accessToken"])
	// refreshToken must NOT be in the body — it is rotated via the cookie.
	_, present := data["refreshToken"]
	assert.False(t, present, "refreshToken must not be in the refresh response body")

	// The rotated cookie must be set and differ from the old token.
	ck := findRefreshCookie(w)
	require.NotNil(t, ck, "refresh must rotate (re-set) the refresh_token cookie")
	assert.NotEmpty(t, ck.Value)
	assert.NotEqual(t, refreshToken, ck.Value, "rotated refresh token must differ from the old one")
	assert.True(t, ck.HttpOnly)
	assert.True(t, ck.Secure)
}

// TestRefresh_MissingCookie asserts a refresh with no cookie is rejected with 401
// (the token never falls back to the request body).
func TestRefresh_MissingCookie(t *testing.T) {
	r, _, _ := buildRouter(t)

	w := postRefreshCookie(t, r, "")

	assert.Equal(t, http.StatusUnauthorized, w.Code)

	var resp map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	errBody := resp["error"].(map[string]any)
	assert.Equal(t, "UNAUTHORIZED", errBody["code"])
}

// TestRefresh_BodyTokenIgnored asserts a refresh token supplied ONLY in the body
// (no cookie) is rejected — the body is no longer a token transport.
func TestRefresh_BodyTokenIgnored(t *testing.T) {
	r, _, _ := buildRouter(t)

	postJSON(t, r, "/v1/auth/register", map[string]any{
		"email":       "isolated@example.com",
		"password":    "superSecurePassword123",
		"displayName": "Iso",
		"accountType": "PERSONAL",
		"legalName":   "Iso Wang",
		"nationalId":  validTWID,
	})

	_, refreshToken := refreshTokenFromLogin(t, r, "isolated@example.com", "superSecurePassword123")

	// Send the (valid) token in the body instead of the cookie. Because the handler
	// reads ONLY the cookie, this must be rejected as an unauthenticated refresh.
	w := postJSON(t, r, "/v1/auth/refresh", map[string]any{
		"refreshToken": refreshToken,
	})

	assert.Equal(t, http.StatusUnauthorized, w.Code, "body-supplied refresh token must be ignored")
}

func TestRefresh_ReuseDetected(t *testing.T) {
	r, _, _ := buildRouter(t)

	postJSON(t, r, "/v1/auth/register", map[string]any{
		"email":       "eve@example.com",
		"password":    "superSecurePassword123",
		"displayName": "Eve",
		"accountType": "PERSONAL",
		"legalName":   "Eve Wang",
		"nationalId":  validTWID,
	})

	_, refreshToken := refreshTokenFromLogin(t, r, "eve@example.com", "superSecurePassword123")

	// Use it once.
	postRefreshCookie(t, r, refreshToken)

	// Use same token again — reuse detection must trigger.
	w := postRefreshCookie(t, r, refreshToken)

	assert.Equal(t, http.StatusUnauthorized, w.Code)

	var resp map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	errBody := resp["error"].(map[string]any)
	assert.Equal(t, "REFRESH_REUSE_DETECTED", errBody["code"])
}

func TestRefresh_InvalidToken(t *testing.T) {
	r, _, _ := buildRouter(t)

	const fakeRefreshToken = "not-a-valid-token" //nolint:gosec // G101: test fixture string, not a real credential

	w := postRefreshCookie(t, r, fakeRefreshToken)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// postLogout issues POST /v1/auth/logout with an Authorization: Bearer access token
// (required by the Auth middleware) and, optionally, the refresh cookie. authHeader
// "" omits the header; refreshToken "" omits the cookie.
func postLogout(t *testing.T, r http.Handler, authHeader, refreshToken string) *httptest.ResponseRecorder {
	t.Helper()

	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/auth/logout", http.NoBody)
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}

	if refreshToken != "" {
		req.AddCookie(&http.Cookie{Name: refreshCookieName, Value: refreshToken})
	}

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	return w
}

// loginAccessToken registers (caller-supplied) + logs in and returns the access
// token plus the refresh-cookie value.
func loginAccessToken(t *testing.T, r http.Handler, email, password string) (accessToken, refreshToken string) {
	t.Helper()

	loginW, refresh := refreshTokenFromLogin(t, r, email, password)

	var resp map[string]any
	require.NoError(t, json.Unmarshal(loginW.Body.Bytes(), &resp))
	data := resp["data"].(map[string]any)
	access, ok := data["accessToken"].(string)
	require.True(t, ok, "login response must carry accessToken")

	return access, refresh
}

// TestLogout_ClearsCookieAndRevokes asserts logout (a) returns 204, (b) clears the
// refresh cookie (MaxAge<0), and (c) revokes the family so the cookie token can no
// longer refresh.
func TestLogout_ClearsCookieAndRevokes(t *testing.T) {
	r, _, _ := buildRouter(t)

	postJSON(t, r, "/v1/auth/register", map[string]any{
		"email":       "grace@example.com",
		"password":    "superSecurePassword123",
		"displayName": "Grace",
		"accountType": "PERSONAL",
		"legalName":   "Grace Wang",
		"nationalId":  validTWID,
	})

	access, refresh := loginAccessToken(t, r, "grace@example.com", "superSecurePassword123")

	w := postLogout(t, r, "Bearer "+access, refresh)
	assert.Equal(t, http.StatusNoContent, w.Code)

	// The cookie must be cleared (browser deletes it: MaxAge < 0).
	ck := findRefreshCookie(w)
	require.NotNil(t, ck, "logout must emit a Set-Cookie that clears refresh_token")
	assert.Less(t, ck.MaxAge, 0, "cleared cookie must have MaxAge < 0")
	assert.Empty(t, ck.Value, "cleared cookie must carry an empty value")
	assert.Equal(t, "/v1/auth", ck.Path, "cleared cookie path must match the original")

	// The revoked token must no longer refresh.
	refreshW := postRefreshCookie(t, r, refresh)
	assert.Equal(t, http.StatusUnauthorized, refreshW.Code, "revoked token must not refresh after logout")
}

// TestLogout_NoCookieStillSucceeds asserts logout is idempotent: with a valid access
// token but no refresh cookie it still returns 204 and clears the cookie.
func TestLogout_NoCookieStillSucceeds(t *testing.T) {
	r, _, _ := buildRouter(t)

	postJSON(t, r, "/v1/auth/register", map[string]any{
		"email":       "heidi@example.com",
		"password":    "superSecurePassword123",
		"displayName": "Heidi",
		"accountType": "PERSONAL",
		"legalName":   "Heidi Wang",
		"nationalId":  validTWID,
	})

	access, _ := loginAccessToken(t, r, "heidi@example.com", "superSecurePassword123")

	w := postLogout(t, r, "Bearer "+access, "")
	assert.Equal(t, http.StatusNoContent, w.Code)

	ck := findRefreshCookie(w)
	require.NotNil(t, ck, "logout must still emit a clearing Set-Cookie even with no incoming cookie")
	assert.Less(t, ck.MaxAge, 0)
}

// TestLogout_Unauthorized asserts logout without a valid access token is 401.
func TestLogout_Unauthorized(t *testing.T) {
	r, _, _ := buildRouter(t)

	w := postLogout(t, r, "", "")
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

	token, err := signer.Issue(u.ID.String(), u.AccountType, u.KYCTier, u.TokenVersion, u.EmailVerified)
	require.NoError(t, err)

	w := getMe(t, r, "Bearer "+token)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	data := resp["data"].(map[string]any)
	assert.Equal(t, "frank@example.com", data["email"])
}

// TestGetMe_EmailVerifiedReflectsDB is load-bearing for the Inc1 web-app gate:
// the frontend hydrates the logged-in user from GET /v1/me and clears the
// "請先驗證 email" banner only when emailVerified is truthy. This test fails if the
// field is dropped from the response map (key absent) OR if it stops reflecting
// the stored users.email_verified value.
func TestGetMe_EmailVerifiedReflectsDB(t *testing.T) {
	tests := []struct {
		name          string
		emailVerified bool
		status        string
	}{
		{name: "verified user → true", emailVerified: true, status: "ACTIVE"},
		{name: "unverified user → false", emailVerified: false, status: "PENDING_VERIFICATION"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r, signer, userStore := buildRouter(t)

			now := time.Now().UTC()
			u := &domain.User{
				ID:            uuid.New(),
				Email:         "verify-state@example.com",
				DisplayName:   "Vera",
				AccountType:   "PERSONAL",
				KYCTier:       0,
				Status:        tc.status,
				EmailVerified: tc.emailVerified,
				CreatedAt:     now,
				UpdatedAt:     now,
			}
			require.NoError(t, userStore.Create(context.Background(), u))

			token, err := signer.Issue(u.ID.String(), u.AccountType, u.KYCTier, u.TokenVersion, u.EmailVerified)
			require.NoError(t, err)

			w := getMe(t, r, "Bearer "+token)
			require.Equal(t, http.StatusOK, w.Code)

			var resp map[string]any
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
			data, ok := resp["data"].(map[string]any)
			require.True(t, ok, "response must carry a data object")

			// The key MUST be present (load-bearing: a missing key would make the
			// frontend treat emailVerified as undefined→falsy and never clear the gate).
			got, present := data["emailVerified"]
			require.True(t, present, "GET /v1/me response must include emailVerified")
			assert.Equal(t, tc.emailVerified, got, "emailVerified must reflect the stored DB value")
		})
	}
}

func TestGetMe_Unauthorized(t *testing.T) {
	r, _, _ := buildRouter(t)

	w := getMe(t, r, "")
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestGetMe_InvalidToken(t *testing.T) {
	r, _, _ := buildRouter(t)

	w := getMe(t, r, "Bearer not.a.jwt")
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}
