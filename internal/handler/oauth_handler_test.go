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
	"github.com/CoverOnes/user/internal/oauth"
	"github.com/CoverOnes/user/internal/service"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	tcredis "github.com/testcontainers/testcontainers-go/modules/redis"
)

// startHandlerRedis spins up a real Redis container for handler-level tests.
func startHandlerRedis(t *testing.T) *redis.Client {
	t.Helper()

	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ctx := context.Background()
	ctr, err := tcredis.Run(ctx, "redis:7-alpine")
	require.NoError(t, err)

	t.Cleanup(func() {
		if termErr := ctr.Terminate(ctx); termErr != nil {
			t.Logf("terminate redis container: %v", termErr)
		}
	})

	addr, err := ctr.ConnectionString(ctx)
	require.NoError(t, err)

	opts, err := redis.ParseURL(addr)
	require.NoError(t, err)

	rdb := redis.NewClient(opts)
	t.Cleanup(func() { _ = rdb.Close() })

	return rdb
}

// stubOAuthProvider is the minimal OAuthProvider needed to exercise Start.
// AuthorizeURL returns a well-known URL so the test can assert the Location header.
type stubOAuthProvider struct{}

func (s *stubOAuthProvider) AuthorizeURL(state, _, _ string) string {
	return "https://accounts.google.com/o/oauth2/v2/auth?state=" + state
}

func (s *stubOAuthProvider) ExchangeCode(_ context.Context, _, _, _ string) (string, error) {
	return "fake-token", nil
}

func (s *stubOAuthProvider) FetchIdentity(_ context.Context, _ string) (*oauth.Identity, error) {
	return nil, nil
}

// TestOAuthHandler_Start_Redirects asserts that GET /v1/auth/oauth/google/start
// returns 302 with a Location header pointing at the provider authorization URL.
// This is the core regression test for the "JSON blob displayed instead of redirect" bug.
func TestOAuthHandler_Start_Redirects(t *testing.T) {
	rdb := startHandlerRedis(t)

	signer, err := jwt.NewEphemeralSigner(10 * time.Minute)
	require.NoError(t, err)

	svc := service.NewOAuthService(&service.OAuthServiceConfig{
		Providers: map[string]service.OAuthProvider{
			"google": &stubOAuthProvider{},
		},
		Redis:           rdb,
		Signer:          signer,
		StateHMACSecret: []byte("handler-test-hmac-secret-32bytes"),
		AccessTTL:       10 * time.Minute,
		RefreshTTLHours: 24,
	})

	r := gin.New()
	oauthH := handler.NewOAuthHandler(svc, "https://app.example.com", "", 24)
	r.GET("/v1/auth/oauth/:provider/start", oauthH.Start)

	req := httptest.NewRequestWithContext(
		context.Background(),
		http.MethodGet, "/v1/auth/oauth/google/start",
		http.NoBody,
	)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusFound, w.Code, "Start must 302-redirect (not return JSON)")

	loc := w.Header().Get("Location")
	assert.NotEmpty(t, loc, "Location header must be set")
	assert.Contains(t, loc, "accounts.google.com", "Location must point at the provider")
}

// TestOAuthHandler_Start_UnknownProvider asserts that an unknown provider returns
// a non-redirect error response (not a panic / 500).
func TestOAuthHandler_Start_UnknownProvider(t *testing.T) {
	rdb := startHandlerRedis(t)

	signer, err := jwt.NewEphemeralSigner(10 * time.Minute)
	require.NoError(t, err)

	svc := service.NewOAuthService(&service.OAuthServiceConfig{
		Providers:       map[string]service.OAuthProvider{"google": &stubOAuthProvider{}},
		Redis:           rdb,
		Signer:          signer,
		StateHMACSecret: []byte("handler-test-hmac-secret-32bytes"),
		AccessTTL:       10 * time.Minute,
		RefreshTTLHours: 24,
	})

	r := gin.New()
	oauthH := handler.NewOAuthHandler(svc, "https://app.example.com", "", 24)
	r.GET("/v1/auth/oauth/:provider/start", oauthH.Start)

	req := httptest.NewRequestWithContext(
		context.Background(),
		http.MethodGet, "/v1/auth/oauth/notareal/start",
		http.NoBody,
	)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	// Must NOT be a 302 and must NOT be 500.
	assert.NotEqual(t, http.StatusFound, w.Code, "unknown provider must not redirect")
	assert.NotEqual(t, http.StatusInternalServerError, w.Code)
}

// buildExchangeRouter wires an OAuthHandler backed by a real Redis container and the
// in-memory fakes (fakeUserStore / fakeRefreshTokenStore from auth_handler_test.go),
// then seeds one user + returns the router and that user's ID so the test can mint a
// one-time exchange code.
func buildExchangeRouter(t *testing.T) (*gin.Engine, *redis.Client, uuid.UUID) {
	t.Helper()

	rdb := startHandlerRedis(t)

	signer, err := jwt.NewEphemeralSigner(10 * time.Minute)
	require.NoError(t, err)

	userStore := newFakeUserStore()
	rtStore := newFakeRefreshTokenStore()

	now := time.Now().UTC()
	u := &domain.User{
		ID:          uuid.New(),
		Email:       "oauth-exchange@example.com",
		DisplayName: "OAuth User",
		AccountType: "PERSONAL",
		KYCTier:     0,
		Status:      domain.UserStatusActive,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	require.NoError(t, userStore.Create(context.Background(), u))

	svc := service.NewOAuthService(&service.OAuthServiceConfig{
		UserStore:         userStore,
		RefreshTokenStore: rtStore,
		Redis:             rdb,
		Signer:            signer,
		Providers:         map[string]service.OAuthProvider{"google": &stubOAuthProvider{}},
		StateHMACSecret:   []byte("handler-test-hmac-secret-32bytes"),
		AccessTTL:         10 * time.Minute,
		RefreshTTLHours:   24,
	})

	r := gin.New()
	// cookieDomain="" (dev), refreshTTLHours=24 — matches the service TTL above.
	oauthH := handler.NewOAuthHandler(svc, "https://app.example.com", "", 24)
	r.POST("/v1/auth/oauth/exchange", oauthH.Exchange)

	return r, rdb, u.ID
}

// seedExchangeCode writes a one-time login code → userID entry into Redis using the
// exact key/format the OAuthService.Exchange consumes (oauth:code:<code> → {"u":id}).
func seedExchangeCode(t *testing.T, rdb *redis.Client, code string, userID uuid.UUID) {
	t.Helper()

	payload, err := json.Marshal(map[string]string{"u": userID.String()})
	require.NoError(t, err)
	require.NoError(t, rdb.Set(context.Background(), "oauth:code:"+code, payload, 5*time.Minute).Err())
}

func postExchange(t *testing.T, r http.Handler, code string) *httptest.ResponseRecorder {
	t.Helper()

	body, err := json.Marshal(map[string]string{"code": code})
	require.NoError(t, err)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/auth/oauth/exchange", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	return w
}

// TestOAuthExchange_SetsCookieNoBodyToken asserts the OAuth exchange (a) returns the
// access token in the body, (b) does NOT return the refresh token in the body, and
// (c) sets the hardened HttpOnly refresh cookie.
func TestOAuthExchange_SetsCookieNoBodyToken(t *testing.T) {
	r, rdb, userID := buildExchangeRouter(t)

	const code = "one-time-exchange-code-abc123"
	seedExchangeCode(t, rdb, code, userID)

	w := postExchange(t, r, code)
	require.Equal(t, http.StatusOK, w.Code)

	var resp map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	data := resp["data"].(map[string]any)
	assert.NotEmpty(t, data["accessToken"], "exchange must return an access token in the body")
	_, present := data["refreshToken"]
	assert.False(t, present, "refreshToken must NOT appear in the exchange body")

	ck := findRefreshCookie(w)
	require.NotNil(t, ck, "exchange must set the refresh_token cookie")
	assert.NotEmpty(t, ck.Value)
	assert.True(t, ck.HttpOnly, "refresh cookie must be HttpOnly")
	assert.True(t, ck.Secure, "refresh cookie must be Secure")
	assert.Equal(t, http.SameSiteStrictMode, ck.SameSite)
	assert.Equal(t, "/v1/auth", ck.Path)
	assert.Equal(t, 24*3600, ck.MaxAge)
}

// TestOAuthExchange_InvalidCode asserts an unknown one-time code is rejected (no
// cookie set).
func TestOAuthExchange_InvalidCode(t *testing.T) {
	r, _, _ := buildExchangeRouter(t)

	w := postExchange(t, r, "no-such-code")
	assert.NotEqual(t, http.StatusOK, w.Code, "unknown code must not succeed")
	assert.Nil(t, findRefreshCookie(w), "no cookie on failed exchange")
}
