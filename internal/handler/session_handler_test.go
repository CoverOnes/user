package handler_test

import (
	"context"
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

// buildSessionRouter returns a minimal Gin engine wired with the session endpoint.
// It shares fakeUserStore / fakeRefreshTokenStore from the same test package.
func buildSessionRouter(t *testing.T) (*gin.Engine, *jwt.Signer, *fakeUserStore) {
	t.Helper()

	signer, err := jwt.NewEphemeralSigner(10 * time.Minute)
	require.NoError(t, err)

	userStore := newFakeUserStore()
	companyStore := &fakeCompanyStore{}
	rtStore := newFakeRefreshTokenStore()

	authSvc := service.NewAuthService(userStore, companyStore, rtStore, nil, signer, 10*time.Minute, 24)

	r := gin.New()
	r.Use(middleware.Recover())

	authMW := middleware.Auth(signer)
	me := r.Group("/v1/me")
	me.Use(authMW)

	sessH := handler.NewSessionHandler(authSvc)
	me.POST("/sessions/revoke-all", sessH.RevokeAll)

	return r, signer, userStore
}

// postWithAuth performs a POST with a Bearer token and no request body.
func postWithAuth(t *testing.T, r http.Handler, path, token string) *httptest.ResponseRecorder {
	t.Helper()

	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, path, http.NoBody)
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	return w
}

// TestRevokeAll_HappyPath verifies that a valid token results in 204 and bumps token_version.
func TestRevokeAll_HappyPath(t *testing.T) {
	r, signer, userStore := buildSessionRouter(t)

	// sessionTestPasswordHash is a structurally-valid but inert argon2id hash for test fixtures.
	// Not a real credential — the value is intentionally synthetic and cannot be used to authenticate.
	//nolint:gosec // G101: test fixture, not a real credential
	sessionTestPasswordHash := "$argon2id$v=19$m=65536,t=3,p=2$xtest$xtest"

	now := time.Now().UTC()
	u := &domain.User{
		ID:           uuid.New(),
		Email:        "revoke@example.com",
		PasswordHash: &sessionTestPasswordHash,
		DisplayName:  "Revoke User",
		AccountType:  "PERSONAL",
		KYCTier:      0,
		Status:       "ACTIVE",
		TokenVersion: 0,
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	require.NoError(t, userStore.Create(context.Background(), u))

	token, err := signer.Issue(u.ID.String(), u.AccountType, u.KYCTier, u.TokenVersion, u.EmailVerified)
	require.NoError(t, err)

	w := postWithAuth(t, r, "/v1/me/sessions/revoke-all", token)
	assert.Equal(t, http.StatusNoContent, w.Code)

	// token_version should be bumped in the fake store.
	got, err := userStore.GetByID(context.Background(), u.ID)
	require.NoError(t, err)
	assert.Equal(t, 1, got.TokenVersion)
}

// TestRevokeAll_Unauthorized verifies that missing auth token returns 401.
func TestRevokeAll_Unauthorized(t *testing.T) {
	r, _, _ := buildSessionRouter(t)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/me/sessions/revoke-all", http.NoBody)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestRevokeAll_InvalidToken verifies that a malformed token returns 401.
func TestRevokeAll_InvalidToken(t *testing.T) {
	r, _, _ := buildSessionRouter(t)

	w := postWithAuth(t, r, "/v1/me/sessions/revoke-all", "not.a.jwt.token")
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}
