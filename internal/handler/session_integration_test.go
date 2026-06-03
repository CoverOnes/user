package handler_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/CoverOnes/user/internal/auth/jwt"
	"github.com/CoverOnes/user/internal/handler"
	"github.com/CoverOnes/user/internal/platform/middleware"
	"github.com/CoverOnes/user/internal/service"
	"github.com/CoverOnes/user/internal/store/postgres"
	migrations "github.com/CoverOnes/user/migrations"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
)

// startTestDBForHandler spins up a Postgres container for handler integration tests.
func startTestDBForHandler(t *testing.T) string {
	t.Helper()

	ctx := context.Background()

	ctr, err := tcpostgres.Run(
		ctx,
		"postgres:17-alpine",
		tcpostgres.WithDatabase("testdb"),
		tcpostgres.WithUsername("testuser"),
		tcpostgres.WithPassword("testpass"),
		tcpostgres.BasicWaitStrategies(),
	)
	require.NoError(t, err)

	t.Cleanup(func() {
		if termErr := ctr.Terminate(ctx); termErr != nil {
			t.Logf("terminate container: %v", termErr)
		}
	})

	dsn, err := ctr.ConnectionString(ctx, "sslmode=disable")
	require.NoError(t, err)

	return dsn
}

// runMigrationsForHandler applies all embedded *.up.sql migration files.
func runMigrationsForHandler(t *testing.T, ctx context.Context, dsn string) {
	t.Helper()

	pool, err := postgres.NewPool(ctx, dsn, "", 0, 0)
	require.NoError(t, err)

	defer pool.Close()

	var upFiles []string

	err = fs.WalkDir(migrations.FS, ".", func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if !d.IsDir() && strings.HasSuffix(path, ".up.sql") {
			upFiles = append(upFiles, path)
		}
		return nil
	})
	require.NoError(t, err)
	require.NotEmpty(t, upFiles)

	sort.Strings(upFiles)

	for _, file := range upFiles {
		data, readErr := migrations.FS.ReadFile(file)
		require.NoError(t, readErr)

		_, execErr := pool.Exec(ctx, string(data))
		require.NoError(t, execErr, fmt.Sprintf("apply migration %s", file))
	}
}

// buildFullRouter constructs a real router backed by a real Postgres pool.
func buildFullRouter(
	t *testing.T,
	signer *jwt.Signer,
	authSvc *service.AuthService,
) *gin.Engine {
	t.Helper()

	r := gin.New()
	r.Use(middleware.Recover())
	r.Use(middleware.RequestID())

	authH := handler.NewAuthHandler(authSvc, signer)
	auth := r.Group("/v1/auth")
	auth.POST("/login", authH.Login)
	auth.POST("/refresh", authH.Refresh)
	auth.POST("/logout", middleware.Auth(signer), authH.Logout)

	authMW := middleware.Auth(signer)
	me := r.Group("/v1/me")
	me.Use(authMW)

	sessH := handler.NewSessionHandler(authSvc)
	me.POST("/sessions/revoke-all", sessH.RevokeAll)

	return r
}

// TestRevokeAll_Integration_RefreshFailsAfterRevoke proves that after POST /v1/me/sessions/revoke-all,
// the user's existing refresh tokens fail /v1/auth/refresh with a version mismatch.
func TestRevokeAll_Integration_RefreshFailsAfterRevoke(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ctx := context.Background()
	dsn := startTestDBForHandler(t)
	runMigrationsForHandler(t, ctx, dsn)

	pool, err := postgres.NewPool(ctx, dsn, "", 0, 0)
	require.NoError(t, err)

	defer pool.Close()

	userStore := postgres.NewUserStore(pool)
	companyStore := postgres.NewCompanyStore(pool)
	rtStore := postgres.NewRefreshTokenStore(pool)
	txMgr := postgres.NewTxManager(pool)

	signer, err := jwt.NewEphemeralSigner(10 * time.Minute)
	require.NoError(t, err)

	authSvc := service.NewAuthService(
		userStore, companyStore, rtStore, txMgr,
		signer, 10*time.Minute, 24,
	)

	r := buildFullRouter(t, signer, authSvc)

	// Register a user via service directly (bypasses password complexity for shorter test setup).
	out, err := authSvc.Register(ctx, service.RegisterInput{
		Email:       "revoke-integration@example.test",
		Password:    "SuperSecurePassword999",
		DisplayName: "Revoke Integration",
		AccountType: "PERSONAL",
	})
	require.NoError(t, err)

	userID := out.User.ID

	// Log in to get a refresh token.
	loginResp := postJSON(t, r, "/v1/auth/login", map[string]any{
		"email":    "revoke-integration@example.test",
		"password": "SuperSecurePassword999",
	})
	require.Equal(t, http.StatusOK, loginResp.Code)

	var loginBody map[string]any
	require.NoError(t, json.Unmarshal(loginResp.Body.Bytes(), &loginBody))

	loginData := loginBody["data"].(map[string]any)
	refreshToken := loginData["refreshToken"].(string)
	accessToken := loginData["accessToken"].(string)

	// Verify refresh works before revoke.
	preRevokeRefresh := postJSON(t, r, "/v1/auth/refresh", map[string]any{
		"refreshToken": refreshToken,
	})

	require.Equal(t, http.StatusOK, preRevokeRefresh.Code)

	var preBody map[string]any
	require.NoError(t, json.Unmarshal(preRevokeRefresh.Body.Bytes(), &preBody))

	// We now have a second refresh token from the rotation.
	newRefreshToken := preBody["data"].(map[string]any)["refreshToken"].(string)

	// Revoke all sessions via the endpoint.
	req := httptest.NewRequestWithContext(ctx, http.MethodPost, "/v1/me/sessions/revoke-all", http.NoBody)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusNoContent, w.Code, "revoke-all should return 204")

	// After revoke: the NEW refresh token from the rotation should fail refresh.
	postRevokeRefresh := postJSON(t, r, "/v1/auth/refresh", map[string]any{
		"refreshToken": newRefreshToken,
	})

	assert.Equal(t, http.StatusUnauthorized, postRevokeRefresh.Code, "refresh must fail after revoke-all")

	// Also verify: the original (used) token still fails (was revoked via family revoke on rotation).
	originalRefresh := postJSON(t, r, "/v1/auth/refresh", map[string]any{
		"refreshToken": refreshToken,
	})
	assert.Equal(t, http.StatusUnauthorized, originalRefresh.Code, "original token must also fail")

	// Confirm the user's token_version was bumped in DB.
	u, err := userStore.GetByID(ctx, userID)
	require.NoError(t, err)
	assert.Equal(t, 1, u.TokenVersion, "token_version must be 1 after one revoke-all")
}
