package mailer_test

import (
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
			},
			wantErr: false,
		},
		{
			name: "valid config without auth (local relay)",
			cfg: mailer.Config{
				Host: "localhost", Port: 1025, From: "no-reply@example.com",
			},
			wantErr: false,
		},
		{
			name: "default send timeout applied when zero",
			cfg: mailer.Config{
				Host: "smtp.example.com", Port: 587, From: "no-reply@example.com",
				SendTimeout: 0,
			},
			wantErr: false,
		},
		{
			name:    "empty host rejected by go-mail",
			cfg:     mailer.Config{Host: "", Port: 587},
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

func TestNewSMTPMailer_DoesNotMutateCallerConfig(t *testing.T) {
	t.Parallel()

	cfg := mailer.Config{Host: "smtp.example.com", Port: 587, SendTimeout: 0}
	_, err := mailer.NewSMTPMailer(&cfg)
	require.NoError(t, err)

	// The constructor copies cfg before defaulting SendTimeout, so the caller's
	// struct is untouched.
	assert.Equal(t, time.Duration(0), cfg.SendTimeout, "caller config must not be mutated")
}
