package mailer_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/CoverOnes/user/internal/mailer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// capturedRequest holds the parts of the HTTP request the stub server
// captures so assertions can inspect them.
type capturedRequest struct {
	method       string
	path         string
	serviceID    string
	serviceToken string
	body         mailer.CommsSendRequest
}

// newCommsStub starts an httptest.Server that always responds with the given
// statusCode and captures the inbound request for assertion.
// Caller must call srv.Close().
func newCommsStub(t *testing.T, statusCode int) (*httptest.Server, *capturedRequest) {
	t.Helper()

	captured := &capturedRequest{}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured.method = r.Method
		captured.path = r.URL.Path
		captured.serviceID = r.Header.Get("X-Service-Id")
		captured.serviceToken = r.Header.Get("X-Service-Token")

		rawBody, err := io.ReadAll(io.LimitReader(r.Body, 64*1024))
		if err != nil {
			http.Error(w, "read body error", http.StatusInternalServerError)
			return
		}

		_ = json.Unmarshal(rawBody, &captured.body)

		w.WriteHeader(statusCode)
		_, _ = w.Write([]byte(`{"data":{"sendId":"test-id","status":"SENT","deduped":false}}`))
	}))

	return srv, captured
}

func TestNewCommsMailer_Validation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		cfg     mailer.CommsConfig
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid config",
			cfg: mailer.CommsConfig{
				BaseURL:    "http://notification:8084",
				S2SToken:   "test-token-min24charslength!",
				AppBaseURL: "http://localhost:5500",
			},
			wantErr: false,
		},
		{
			name: "missing BaseURL",
			cfg: mailer.CommsConfig{
				S2SToken:   "test-token",
				AppBaseURL: "http://localhost:5500",
			},
			wantErr: true,
			errMsg:  "BaseURL is required",
		},
		{
			name: "missing AppBaseURL",
			cfg: mailer.CommsConfig{
				BaseURL:  "http://notification:8084",
				S2SToken: "test-token",
			},
			wantErr: true,
			errMsg:  "AppBaseURL is required",
		},
		{
			name: "missing S2SToken",
			cfg: mailer.CommsConfig{
				BaseURL:    "http://notification:8084",
				AppBaseURL: "http://localhost:5500",
			},
			wantErr: true,
			errMsg:  "S2SToken is required",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			cfg := tc.cfg
			m, err := mailer.NewCommsMailer(&cfg)

			if tc.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.errMsg)
				assert.Nil(t, m)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, m)
			}
		})
	}
}

//nolint:gosec // G101: testS2SToken is a test fixture token, not a real credential
const testS2SToken = "shared-s2s-token-for-test-24ch"

func TestCommsMailer_SendVerification_HappyPath(t *testing.T) {
	t.Parallel()

	srv, captured := newCommsStub(t, http.StatusAccepted)
	defer srv.Close()

	const (
		token      = "abc123_DEF-456"
		to         = "user@example.com"
		appBaseURL = "http://localhost:5500"
	)

	m, err := mailer.NewCommsMailer(&mailer.CommsConfig{
		BaseURL:     srv.URL,
		ServiceID:   "user-service",
		S2SToken:    testS2SToken,
		AppBaseURL:  appBaseURL,
		SendTimeout: 5 * time.Second,
	})
	require.NoError(t, err)

	err = m.SendVerification(context.Background(), to, token)
	require.NoError(t, err)

	// Assert correct HTTP method and path.
	assert.Equal(t, http.MethodPost, captured.method)
	assert.Equal(t, "/v1/comms/send", captured.path)

	// Assert S2S identity headers.
	assert.Equal(t, "user-service", captured.serviceID)
	assert.Equal(t, testS2SToken, captured.serviceToken)

	// Assert request body shape.
	assert.Equal(t, "EMAIL", captured.body.Channel)
	assert.Equal(t, to, captured.body.To)
	assert.Equal(t, "email_verify", captured.body.TemplateID)
	assert.Equal(t, "en", captured.body.Locale)

	// Assert template vars: verifyURL and token.
	wantURL := "http://localhost:5500/verify-email?token=abc123_DEF-456"
	assert.Equal(t, wantURL, captured.body.Vars["verifyURL"])
	assert.Equal(t, token, captured.body.Vars["token"])

	// Assert idempotency key is non-empty.
	assert.NotEmpty(t, captured.body.IdempotencyKey)

	// Same token → same idempotency key (deterministic): call again, key must be identical.
	firstKey := captured.body.IdempotencyKey

	m2, err := mailer.NewCommsMailer(&mailer.CommsConfig{
		BaseURL:    srv.URL,
		S2SToken:   testS2SToken,
		AppBaseURL: appBaseURL,
	})
	require.NoError(t, err)

	err = m2.SendVerification(context.Background(), to, token)
	require.NoError(t, err)

	assert.Equal(t, firstKey, captured.body.IdempotencyKey, "idempotency key must be deterministic for same token")
}

func TestCommsMailer_SendVerification_NonAcceptedStatus(t *testing.T) {
	t.Parallel()

	srv, _ := newCommsStub(t, http.StatusInternalServerError)
	defer srv.Close()

	m, err := mailer.NewCommsMailer(&mailer.CommsConfig{
		BaseURL:    srv.URL,
		S2SToken:   testS2SToken,
		AppBaseURL: "http://localhost:5500",
	})
	require.NoError(t, err)

	err = m.SendVerification(context.Background(), "user@example.com", "sometoken")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unexpected status 500")
}

func TestCommsMailer_SendVerification_ServerUnreachable(t *testing.T) {
	t.Parallel()

	m, err := mailer.NewCommsMailer(&mailer.CommsConfig{
		BaseURL:     "http://127.0.0.1:19999", // nothing listening here
		S2SToken:    testS2SToken,
		AppBaseURL:  "http://localhost:5500",
		SendTimeout: 500 * time.Millisecond,
	})
	require.NoError(t, err)

	err = m.SendVerification(context.Background(), "user@example.com", "sometoken")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "send request")
}

func TestCommsMailer_SendVerification_TokenURLEncoded(t *testing.T) {
	t.Parallel()
	// Ensure the raw token is URL-escaped when embedded in verifyURL
	// (edge case: tokens with base64 padding or special chars).
	srv, captured := newCommsStub(t, http.StatusAccepted)
	defer srv.Close()

	// Use a descriptive const name to avoid gosec G101 (not a credential).
	const base64TokenWithSpecialChars = "ab+cd/ef==" //nolint:gosec // G101 false positive: this is a test token value, not a credential

	m, err := mailer.NewCommsMailer(&mailer.CommsConfig{
		BaseURL:    srv.URL,
		S2SToken:   testS2SToken,
		AppBaseURL: "http://localhost:5500",
	})
	require.NoError(t, err)

	require.NoError(t, m.SendVerification(context.Background(), "u@e.com", base64TokenWithSpecialChars))

	verifyURL := captured.body.Vars["verifyURL"]
	assert.Contains(t, verifyURL, "http://localhost:5500/verify-email?token=")
	// The raw '+' must be percent-encoded as %2B in the URL.
	assert.Contains(t, verifyURL, "%2B")
	// The raw token is passed separately (for template secondary fallback).
	assert.Equal(t, base64TokenWithSpecialChars, captured.body.Vars["token"])
}
