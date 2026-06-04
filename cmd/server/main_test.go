package main

import (
	"bytes"
	"context"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDevLogMailer_SendVerification(t *testing.T) {
	tests := []struct {
		name       string
		appBaseURL string
		want       []string
	}{
		{
			name:       "logs clickable URL when app base URL is configured",
			appBaseURL: "http://dev.coverones.test:5500",
			want:       []string{"verify_url", "http://dev.coverones.test:5500/verify-email?token=raw-token"},
		},
		{
			name:       "logs token recovery path when app base URL is absent",
			appBaseURL: "",
			want:       []string{"verify_token", "raw-token", "set USER_APP_BASE_URL to log a clickable verification link"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			original := slog.Default()
			slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{})))
			t.Cleanup(func() { slog.SetDefault(original) })

			m := devLogMailer{appBaseURL: tc.appBaseURL}
			require.NoError(t, m.SendVerification(context.Background(), "dev@example.test", "raw-token"))

			got := buf.String()
			for _, want := range tc.want {
				assert.Contains(t, got, want)
			}
		})
	}
}
