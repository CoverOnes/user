// Package oauth provides Google OIDC and LINE Login v2.1 provider plumbing:
// authorization URL construction, code→token exchange, and userinfo fetch.
// It does NOT handle the state/PKCE session store or the linking logic —
// those live in service.OAuthService.
package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/CoverOnes/user/internal/domain"
)

// Identity is the normalized result of a provider userinfo call.
type Identity struct {
	// ProviderSubject is the provider-side stable user identifier (Google "sub", LINE "userId").
	ProviderSubject string
	// Email is the email address returned by the provider (may be empty for LINE).
	Email string
	// EmailVerified is true when the provider confirmed the email belongs to the user.
	EmailVerified bool
}

// ProviderConfig holds the OAuth 2.0 / OIDC settings for a single provider.
type ProviderConfig struct {
	// ClientID is the OAuth application client ID.
	ClientID string
	// ClientSecret is the OAuth application client secret.
	ClientSecret string
	// RedirectURI is the registered callback URL for this provider.
	// AuthorizeURL and ExchangeCode use this value when the caller passes "".
	RedirectURI string
	// AuthURL is the provider authorization endpoint.
	AuthURL string
	// TokenURL is the provider token endpoint.
	TokenURL string
	// UserinfoURL is the provider userinfo endpoint.
	UserinfoURL string
	// Scopes is the space-separated scope string appended to the authorization URL.
	Scopes string
}

// httpClient is the shared HTTP client for provider calls.
// A single shared client reuses connections; each call sets its own deadline via context.
var httpClient = &http.Client{Timeout: 15 * time.Second}

// GoogleConfig builds the provider config for Google OIDC.
// The redirectURI is stored and used by AuthorizeURL/ExchangeCode when no
// per-call redirect URI is specified (empty string at call site).
func GoogleConfig(clientID, clientSecret, redirectURI string) *ProviderConfig {
	return &ProviderConfig{ //nolint:gosec // G101: struct contains "Secret" field name; values come from env, not hardcoded
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURI:  redirectURI,
		AuthURL:      "https://accounts.google.com/o/oauth2/v2/auth",
		TokenURL:     "https://oauth2.googleapis.com/token",
		UserinfoURL:  "https://openidconnect.googleapis.com/v1/userinfo",
		Scopes:       "openid email profile",
	}
}

// LINEConfig builds the provider config for LINE Login v2.1.
// The redirectURI is stored and used by AuthorizeURL/ExchangeCode when no
// per-call redirect URI is specified (empty string at call site).
func LINEConfig(channelID, channelSecret, redirectURI string) *ProviderConfig {
	return &ProviderConfig{ //nolint:gosec // G101: struct contains "Secret" field name; values come from env, not hardcoded
		ClientID:     channelID,
		ClientSecret: channelSecret,
		RedirectURI:  redirectURI,
		AuthURL:      "https://access.line.me/oauth2/v2.1/authorize",
		TokenURL:     "https://api.line.me/oauth2/v2.1/token",
		UserinfoURL:  "https://api.line.me/v2/profile",
		Scopes:       "profile openid email",
	}
}

// AuthorizeURL builds the provider authorization URL with PKCE and state.
// codeChallenge must be the base64url-encoded SHA-256 of the PKCE verifier.
// If redirectURI is empty, the config's RedirectURI is used.
func (p *ProviderConfig) AuthorizeURL(state, codeChallenge, redirectURI string) string {
	if redirectURI == "" {
		redirectURI = p.RedirectURI
	}

	v := url.Values{}
	v.Set("response_type", "code")
	v.Set("client_id", p.ClientID)
	v.Set("redirect_uri", redirectURI)
	v.Set("scope", p.Scopes)
	v.Set("state", state)
	v.Set("code_challenge", codeChallenge)
	v.Set("code_challenge_method", "S256")

	return p.AuthURL + "?" + v.Encode()
}

// ExchangeCode exchanges an authorization code for an access token.
// Returns the raw access token string on success.
// If redirectURI is empty, the config's RedirectURI is used.
func (p *ProviderConfig) ExchangeCode(ctx context.Context, code, codeVerifier, redirectURI string) (string, error) {
	if redirectURI == "" {
		redirectURI = p.RedirectURI
	}

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", redirectURI)
	form.Set("client_id", p.ClientID)
	form.Set("client_secret", p.ClientSecret)
	form.Set("code_verifier", codeVerifier)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("build token request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("%w: %w", domain.ErrOAuthExchangeFailed, err)
	}

	defer func() {
		_ = resp.Body.Close()
	}()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return "", fmt.Errorf("read token response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("%w: provider returned %d", domain.ErrOAuthExchangeFailed, resp.StatusCode)
	}

	var tok struct {
		AccessToken string `json:"access_token"`
		IDToken     string `json:"id_token"`
		Error       string `json:"error"`
	}

	if err := json.Unmarshal(body, &tok); err != nil {
		return "", fmt.Errorf("parse token response: %w", err)
	}

	if tok.Error != "" {
		return "", fmt.Errorf("%w: %s", domain.ErrOAuthExchangeFailed, tok.Error)
	}

	if tok.AccessToken == "" {
		return "", fmt.Errorf("%w: no access_token in response", domain.ErrOAuthExchangeFailed)
	}

	return tok.AccessToken, nil
}

// FetchIdentity calls the userinfo endpoint and returns the normalized Identity.
func (p *ProviderConfig) FetchIdentity(ctx context.Context, accessToken string) (*Identity, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.UserinfoURL, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("build userinfo request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("userinfo fetch: %w", err)
	}

	defer func() {
		_ = resp.Body.Close()
	}()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return nil, fmt.Errorf("read userinfo response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("userinfo returned %d", resp.StatusCode)
	}

	// Both Google and LINE return JSON but with different field names.
	// Google: sub, email, email_verified
	// LINE: userId, email (may be absent), emailVerified (non-standard; absent for LINE)
	var raw struct {
		// Google OIDC userinfo
		Sub           string `json:"sub"`
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
		// LINE profile — userId is the stable subject
		UserID string `json:"userId"`
	}

	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("parse userinfo: %w", err)
	}

	subject := raw.Sub
	if subject == "" {
		// LINE Login uses userId
		subject = raw.UserID
	}

	if subject == "" {
		return nil, fmt.Errorf("userinfo missing subject (sub/userId)")
	}

	return &Identity{
		ProviderSubject: subject,
		Email:           raw.Email,
		EmailVerified:   raw.EmailVerified,
	}, nil
}
