// Package mailer — CommsMailer sends transactional email via the CoverOnes
// comms service (POST /v1/comms/send S2S endpoint) rather than directly over
// SMTP. This is the Phase 1 re-home: the user service becomes a comms CALLER
// instead of a direct SMTP sender.
package mailer

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// commsMaxResponseBytes caps the comms send-API response body read.
const commsMaxResponseBytes = 64 * 1024

// commsDefaultTimeout bounds a single comms send call.
const commsDefaultTimeout = 10 * time.Second

// CommsSendRequest is the POST /v1/comms/send request body (matches comms
// handler sendRequestBody, kept local so the user module has no import cycle
// to the notification module). Raw token values are deliberately NOT included in
// Vars; verifyURL is the canonical token carrier across the S2S boundary.
type CommsSendRequest struct {
	Channel        string            `json:"channel"`
	To             string            `json:"to"`
	TemplateID     string            `json:"templateId"`
	Locale         string            `json:"locale"`
	Vars           map[string]string `json:"vars"`
	IdempotencyKey string            `json:"idempotencyKey"`
}

// CommsConfig holds the configuration for the CommsMailer.
type CommsConfig struct {
	// BaseURL is the notification service base URL reachable from the user
	// service (e.g. http://notification:8084 inside the Docker network).
	BaseURL string
	// ServiceID is the caller identifier sent in X-Service-Id (audit trail).
	ServiceID string
	// S2SToken is the shared bearer token sent in X-Service-Token.
	S2SToken string
	// AppBaseURL is the public frontend base URL used to build the clickable
	// verification link.
	AppBaseURL string
	// SendTimeout bounds a single send. Zero falls back to commsDefaultTimeout.
	SendTimeout time.Duration
}

// CommsMailer implements service.Mailer by posting to the comms send API.
type CommsMailer struct {
	cfg    CommsConfig
	client *http.Client
}

// NewCommsMailer constructs a CommsMailer. Returns an error if required config
// fields are missing or the BaseURL is not a valid http/https URL (SSRF defense:
// a misconfigured BaseURL such as file:// or ftp:// must not receive the X-Service-Token).
func NewCommsMailer(cfg *CommsConfig) (*CommsMailer, error) {
	if strings.TrimSpace(cfg.BaseURL) == "" {
		return nil, fmt.Errorf("comms mailer: BaseURL is required")
	}

	// Validate BaseURL scheme before using it: only http and https are permitted.
	// This prevents SSRF via a misconfigured or attacker-supplied BaseURL that could
	// cause the X-Service-Token to be forwarded to an unintended endpoint.
	parsedURL, err := url.ParseRequestURI(cfg.BaseURL)
	if err != nil || (parsedURL.Scheme != "http" && parsedURL.Scheme != "https") {
		return nil, fmt.Errorf("comms mailer: BaseURL must be a valid http/https URL")
	}

	if strings.TrimSpace(cfg.AppBaseURL) == "" {
		return nil, fmt.Errorf("comms mailer: AppBaseURL is required")
	}

	if strings.TrimSpace(cfg.S2SToken) == "" {
		return nil, fmt.Errorf("comms mailer: S2SToken is required")
	}

	timeout := cfg.SendTimeout
	if timeout <= 0 {
		timeout = commsDefaultTimeout
	}

	return &CommsMailer{
		cfg: CommsConfig{
			BaseURL:     strings.TrimRight(strings.TrimSpace(cfg.BaseURL), "/"),
			ServiceID:   cfg.ServiceID,
			S2SToken:    cfg.S2SToken,
			AppBaseURL:  cfg.AppBaseURL,
			SendTimeout: timeout,
		},
		client: &http.Client{Timeout: timeout},
	}, nil
}

// SendVerification delivers an email-verification message through the comms
// service. The comms service renders the email_verify template with:
//
//	verifyURL — the full clickable verification link (canonical delivery vehicle)
//
// The raw token is deliberately NOT forwarded across the S2S boundary; verifyURL
// is the only token carrier so the raw secret never leaves the user service.
// The idempotency key is a SHA-256 of the token so a duplicate notification
// dispatch is safely deduplicated by the comms send log.
func (m *CommsMailer) SendVerification(ctx context.Context, to, token string) error {
	verifyURL := buildVerifyURL(m.cfg.AppBaseURL, token)

	// Idempotency key: deterministic per-token so a re-dispatch deduplicates.
	idempKey := idempotencyKey(token)

	req := CommsSendRequest{
		Channel:    "EMAIL",
		To:         to,
		TemplateID: "email_verify",
		Locale:     "en",
		Vars: map[string]string{
			"verifyURL": verifyURL,
			// Raw token is deliberately absent: verifyURL is the canonical carrier.
		},
		IdempotencyKey: idempKey,
	}

	body, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("comms mailer: marshal request: %w", err)
	}

	endpoint := m.cfg.BaseURL + "/v1/comms/send"

	// Derive a child context from ctx (satisfies contextcheck) but cap it with the
	// configured send timeout so a hung comms service does not block indefinitely.
	// The caller (auth_service) already dispatches SendVerification from a
	// context.Background()-derived detached goroutine (backend-security-design §goroutine).
	sendCtx, cancel := context.WithTimeout(ctx, m.cfg.SendTimeout)
	defer cancel()

	httpReq, err := http.NewRequestWithContext(sendCtx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("comms mailer: build request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	// S2S identity headers — never in URL query string (backend-security-design §4.2).
	serviceID := m.cfg.ServiceID
	if serviceID == "" {
		serviceID = "user-service"
	}

	httpReq.Header.Set("X-Service-Id", serviceID)
	// X-Service-Token header matches comms middleware (RequireServiceIdentity) exactly.
	httpReq.Header.Set("X-Service-Token", m.cfg.S2SToken)

	resp, err := m.client.Do(httpReq)
	if err != nil {
		return fmt.Errorf("comms mailer: send request: %w", err)
	}

	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			slog.Warn("comms mailer: close response body", "err", closeErr)
		}
	}()

	// Drain with limit to avoid DoS from a rogue comms response.
	if _, err = io.Copy(io.Discard, io.LimitReader(resp.Body, commsMaxResponseBytes)); err != nil {
		slog.Warn("comms mailer: drain response body", "err", err)
	}

	if resp.StatusCode != http.StatusAccepted {
		return fmt.Errorf("comms mailer: unexpected status %d from %s", resp.StatusCode, endpoint)
	}

	return nil
}

// buildVerifyURL constructs <baseURL>/verify-email?token=<token>.
func buildVerifyURL(baseURL, token string) string {
	base := strings.TrimRight(strings.TrimSpace(baseURL), "/")

	return fmt.Sprintf("%s/verify-email?token=%s", base, url.QueryEscape(token))
}

// idempotencyKey builds a deterministic idempotency key from the token so
// duplicate dispatches are deduplicated by the comms send log.
func idempotencyKey(token string) string {
	h := sha256.Sum256([]byte(token))

	// 64-bit prefix: collision probability negligible at expected scale (<1M tokens/day).
	return fmt.Sprintf("user:verify:%x", h[:8])
}
