package middleware_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/CoverOnes/user/internal/platform/middleware"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// buildServiceIdentityRouter returns a minimal Gin engine for testing RequireServiceIdentity.
func buildServiceIdentityRouter(t *testing.T, token string) *gin.Engine {
	t.Helper()

	r := gin.New()
	r.Use(middleware.Recover())
	r.POST("/protected", middleware.RequireServiceIdentity(token), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	return r
}

// issueRequest issues a POST /protected with the given X-Service-Token header value.
// Pass an empty string to omit the header.
func issueRequest(t *testing.T, r *gin.Engine, headerValue string) *httptest.ResponseRecorder {
	t.Helper()

	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/protected", http.NoBody)
	if headerValue != "" {
		req.Header.Set("X-Service-Token", headerValue)
	}

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	return w
}

func TestRequireServiceIdentity(t *testing.T) {
	const expectedToken = "a-valid-s2s-service-token-for-testing" //nolint:gosec // G101: test fixture — not a real credential

	r := buildServiceIdentityRouter(t, expectedToken)

	tests := []struct {
		name        string
		headerValue string
		wantStatus  int
	}{
		{
			name:        "correct token passes",
			headerValue: expectedToken,
			wantStatus:  http.StatusOK,
		},
		{
			name:        "wrong token returns 401",
			headerValue: "wrong-token",
			wantStatus:  http.StatusUnauthorized,
		},
		{
			name:        "missing token returns 401",
			headerValue: "",
			wantStatus:  http.StatusUnauthorized,
		},
		{
			name:        "token with leading whitespace still passes (header trimmed)",
			headerValue: "  " + expectedToken + "  ",
			wantStatus:  http.StatusOK,
		},
		{
			name:        "empty string in header returns 401",
			headerValue: " ",
			wantStatus:  http.StatusUnauthorized,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			w := issueRequest(t, r, tc.headerValue)
			assert.Equal(t, tc.wantStatus, w.Code)
		})
	}
}

func TestRequireServiceIdentity_PanicsOnEmptyToken(t *testing.T) {
	assert.Panics(t, func() {
		middleware.RequireServiceIdentity("")
	}, "must panic when expectedToken is empty — misconfiguration guard")
}

func TestRequireServiceIdentity_UnauthorizedBodyShape(t *testing.T) {
	r := buildServiceIdentityRouter(t, "some-token")

	w := issueRequest(t, r, "wrong")
	require.Equal(t, http.StatusUnauthorized, w.Code)

	// The 401 body must NOT reveal token details — generic message only.
	body := w.Body.String()
	assert.Contains(t, body, "UNAUTHORIZED")
	assert.Contains(t, body, "service authentication required")
	assert.NotContains(t, body, "some-token")
	assert.NotContains(t, body, "wrong")
}
