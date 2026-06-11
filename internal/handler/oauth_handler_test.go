package handler_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/CoverOnes/user/internal/auth/jwt"
	"github.com/CoverOnes/user/internal/handler"
	"github.com/CoverOnes/user/internal/oauth"
	"github.com/CoverOnes/user/internal/service"
	"github.com/gin-gonic/gin"
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
	oauthH := handler.NewOAuthHandler(svc, "https://app.example.com")
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
	oauthH := handler.NewOAuthHandler(svc, "https://app.example.com")
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
