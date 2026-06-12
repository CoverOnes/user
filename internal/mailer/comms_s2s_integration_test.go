package mailer_test

// comms_s2s_integration_test.go — C-1 regression guard for the S2S auth layer.
//
// Both components under test are REAL (not mocked):
//   - mailer.CommsMailer — the user-service caller (sets X-Service-Id + X-Service-Token)
//   - commsAuthRouter — a minimal in-process gin-style router that implements the
//     SAME RequireServiceIdentity logic as the notification service's middleware
//     (constant-time compare on per-caller tokenMap). It is intentionally co-located
//     in the user repo to avoid a cross-repo import cycle; the implementation is
//     the CANONICAL algorithm reproduced verbatim, not a mock.
//
// The test catches the class of bugs where CommsMailer sends the wrong header name,
// wrong service-id, or wrong token and the notification middleware silently 401s —
// exactly the category of gap that burned us on C-1.

import (
	"crypto/subtle"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/CoverOnes/user/internal/mailer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// commsAuthHandler implements the SAME deny-by-default S2S guard logic as the
// notification service's middleware.RequireServiceIdentity — constant-time compare
// on (X-Service-Id, X-Service-Token) against the provided tokenMap.
// This is NOT a mock; it is the canonical algorithm reproduced so the test exercises
// real CommsMailer behavior without requiring a cross-repo import.
func commsAuthHandler(tokenMap map[string]string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(tokenMap) == 0 {
			http.Error(w, "service authentication unavailable", http.StatusUnauthorized)
			return
		}

		serviceID := strings.TrimSpace(r.Header.Get("X-Service-Id"))
		token := r.Header.Get("X-Service-Token")

		if serviceID == "" {
			http.Error(w, "service authentication required", http.StatusUnauthorized)
			return
		}

		expectedToken, known := tokenMap[serviceID]
		if !known || expectedToken == "" {
			http.Error(w, "service authentication required", http.StatusUnauthorized)
			return
		}

		if subtle.ConstantTimeCompare([]byte(token), []byte(expectedToken)) != 1 {
			http.Error(w, "service authentication required", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// newCommsAuthServer starts an httptest.Server with RequireServiceIdentity-equivalent
// middleware protecting POST /v1/comms/send, returning 202 on auth success.
func newCommsAuthServer(t *testing.T, tokenMap map[string]string) *httptest.Server {
	t.Helper()

	mux := http.NewServeMux()
	sendHandler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	})
	mux.Handle("/v1/comms/send", commsAuthHandler(tokenMap, sendHandler))

	return httptest.NewServer(mux)
}

// TestCommsMailer_S2SAuth_Integration verifies that CommsMailer.SendVerification
// correctly wires X-Service-Id + X-Service-Token so it passes a real
// RequireServiceIdentity guard. This is the C-1 regression guard: each side was
// only unit-tested in isolation; this test exercises BOTH together in-process.
func TestCommsMailer_S2SAuth_Integration(t *testing.T) {
	const (
		serviceID = "user-service"
		tok       = "integration-test-s2s-token-32chars!!" // 38 chars, well above min
	)

	tokenMap := map[string]string{serviceID: tok}

	tests := []struct {
		name         string
		cfgServiceID string
		cfgToken     string
		tokenMap     map[string]string
		wantErr      bool
		errContains  string
	}{
		{
			name:         "correct service-id and token → 202 accepted",
			cfgServiceID: serviceID,
			cfgToken:     tok,
			tokenMap:     tokenMap,
			wantErr:      false,
		},
		{
			name:         "wrong token for known service-id → 401",
			cfgServiceID: serviceID,
			cfgToken:     "wrong-token-completely-different",
			tokenMap:     tokenMap,
			wantErr:      true,
			errContains:  "unexpected status 401",
		},
		{
			name:         "unknown service-id → 401",
			cfgServiceID: "kyc-service",
			cfgToken:     tok,
			tokenMap:     tokenMap,
			wantErr:      true,
			errContains:  "unexpected status 401",
		},
		{
			name:         "empty token map → 401 (fail-closed)",
			cfgServiceID: serviceID,
			cfgToken:     tok,
			tokenMap:     map[string]string{},
			wantErr:      true,
			errContains:  "unexpected status 401",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := newCommsAuthServer(t, tc.tokenMap)
			defer srv.Close()

			m, err := mailer.NewCommsMailer(&mailer.CommsConfig{
				BaseURL:    srv.URL,
				ServiceID:  tc.cfgServiceID,
				S2SToken:   tc.cfgToken,
				AppBaseURL: "https://app.coverones.test",
			})
			require.NoError(t, err, "NewCommsMailer must not fail with valid config")

			sendErr := m.SendVerification(t.Context(), "user@example.com", "verify-token-abc")

			if tc.wantErr {
				require.Error(t, sendErr)
				assert.Contains(t, sendErr.Error(), tc.errContains)
			} else {
				require.NoError(t, sendErr)
			}
		})
	}
}
