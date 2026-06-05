package mailer_test

import (
	"strings"
	"testing"
	"time"

	"github.com/CoverOnes/user/internal/mailer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewSMTPMailer(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		cfg     mailer.Config
		wantErr bool
	}{
		{
			name: "valid config with auth",
			cfg: mailer.Config{
				Host: "smtp.example.com", Port: 587,
				Username: "user", Password: "pass", From: "no-reply@example.com",
				AppBaseURL: "https://app.coverones.com",
			},
			wantErr: false,
		},
		{
			name: "valid config without auth (local relay)",
			cfg: mailer.Config{
				Host: "localhost", Port: 1025, From: "no-reply@example.com",
				AppBaseURL: "http://dev.coverones.test:5500",
			},
			wantErr: false,
		},
		{
			name: "default send timeout applied when zero",
			cfg: mailer.Config{
				Host: "smtp.example.com", Port: 587, From: "no-reply@example.com",
				AppBaseURL:  "https://app.coverones.com",
				SendTimeout: 0,
			},
			wantErr: false,
		},
		{
			name: "app base URL required",
			cfg: mailer.Config{
				Host: "smtp.example.com", Port: 587, From: "no-reply@example.com",
				AppBaseURL: "",
			},
			wantErr: true,
		},
		{
			name:    "empty host rejected by go-mail",
			cfg:     mailer.Config{Host: "", Port: 587, AppBaseURL: "https://app.coverones.com"},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			cfg := tc.cfg
			m, err := mailer.NewSMTPMailer(&cfg)
			if tc.wantErr {
				require.Error(t, err)
				assert.Nil(t, m)

				return
			}

			require.NoError(t, err)
			assert.NotNil(t, m)
		})
	}
}

// TestRenderVerification_ContainsClickableURL is load-bearing for the Inc1 MAJOR
// finding: the /register/verify-sent screen promises a clickable link, so the
// rendered email MUST contain <AppBaseURL>/verify-email?token=<token> as the
// primary CTA in BOTH the plain-text and HTML parts. The test would fail if the
// URL were dropped or built from the wrong base.
func TestRenderVerification_ContainsClickableURL(t *testing.T) {
	t.Parallel()

	const token = "abc123_DEF-456" // representative base64url token (no padding chars)

	tests := []struct {
		name    string
		baseURL string
		wantURL string
	}{
		{
			name:    "custom base URL",
			baseURL: "https://app.coverones.com",
			wantURL: "https://app.coverones.com/verify-email?token=abc123_DEF-456",
		},
		{
			name:    "trailing slash on base URL is trimmed",
			baseURL: "https://app.coverones.com/",
			wantURL: "https://app.coverones.com/verify-email?token=abc123_DEF-456",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			cfg := mailer.Config{
				Host: "smtp.example.com", Port: 587, From: "no-reply@example.com",
				AppBaseURL: tc.baseURL,
			}
			m, err := mailer.NewSMTPMailer(&cfg)
			require.NoError(t, err)

			textBody, htmlBody := m.RenderVerification(token)

			// Primary CTA URL present in BOTH parts.
			assert.Contains(t, textBody, tc.wantURL, "plain-text body must contain the clickable verify URL")
			assert.Contains(t, htmlBody, tc.wantURL, "html body must contain the clickable verify URL")

			// HTML part exposes the URL as a clickable anchor.
			assert.Contains(t, htmlBody, `href="`+tc.wantURL+`"`, "html body must link the verify URL as an anchor")

			// Raw token retained only as a secondary fallback line.
			assert.Contains(t, textBody, token, "plain-text body keeps the raw token as fallback")

			// The URL is the PRIMARY instruction: it appears before the fallback token
			// mention in the plain-text body.
			urlIdx := strings.Index(textBody, tc.wantURL)
			tokenLineIdx := strings.LastIndex(textBody, token)
			require.GreaterOrEqual(t, urlIdx, 0)
			assert.Less(t, urlIdx, tokenLineIdx, "verify URL must be presented before the fallback token")
		})
	}
}

func TestNewSMTPMailer_DoesNotMutateCallerConfig(t *testing.T) {
	t.Parallel()

	cfg := mailer.Config{Host: "smtp.example.com", Port: 587, AppBaseURL: "https://app.coverones.com", SendTimeout: 0}
	_, err := mailer.NewSMTPMailer(&cfg)
	require.NoError(t, err)

	// The constructor copies cfg before defaulting SendTimeout, so the caller's
	// struct is untouched.
	assert.Equal(t, time.Duration(0), cfg.SendTimeout, "caller config must not be mutated")
}
