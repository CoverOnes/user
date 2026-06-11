package service

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/CoverOnes/user/internal/auth/jwt"
	"github.com/CoverOnes/user/internal/auth/refresh"
	"github.com/CoverOnes/user/internal/domain"
	"github.com/CoverOnes/user/internal/oauth"
	"github.com/CoverOnes/user/internal/store"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

// oauthStateTTL is how long the state+PKCE entry lives in Redis.
const oauthStateTTL = 10 * time.Minute

// oauthOneTimeTTL is how long a one-time login code is valid.
const oauthOneTimeTTL = 5 * time.Minute

// oauthStateKeyPrefix is the Redis key prefix for OAuth state entries.
const oauthStateKeyPrefix = "oauth:state:"

// oauthCodeKeyPrefix is the Redis key prefix for one-time login codes.
const oauthCodeKeyPrefix = "oauth:code:"

// oauthStateEntry is serialized into Redis to link state→PKCE verifier.
type oauthStateEntry struct {
	CodeVerifier string `json:"cv"`
	Provider     string `json:"p"`
	// ForBind, when non-empty, is the authenticated user ID for the Bind flow.
	ForBind string `json:"b,omitempty"`
}

// oauthCodeEntry is serialized into Redis for the one-time login code.
type oauthCodeEntry struct {
	UserID string `json:"u"`
}

// OAuthProvider abstracts the provider-specific HTTP operations
// so the service is testable without real HTTP calls.
type OAuthProvider interface {
	AuthorizeURL(state, codeChallenge, redirectURI string) string
	ExchangeCode(ctx context.Context, code, codeVerifier, redirectURI string) (string, error)
	FetchIdentity(ctx context.Context, accessToken string) (*oauth.Identity, error)
}

// OAuthService implements the OAuth social login flow (Design A — no auto-link).
type OAuthService struct {
	users         store.UserStore
	identities    store.AuthIdentityStore
	refreshTokens store.RefreshTokenStore
	signer        *jwt.Signer
	redisClient   *redis.Client
	providers     map[string]OAuthProvider
	// stateHMACKey signs and verifies the state parameter to prevent CSRF.
	stateHMACKey []byte
	accessTTL    time.Duration
	refreshTTLH  int
}

// OAuthServiceConfig bundles the dependencies for NewOAuthService.
type OAuthServiceConfig struct {
	UserStore         store.UserStore
	AuthIdentityStore store.AuthIdentityStore
	RefreshTokenStore store.RefreshTokenStore
	Signer            *jwt.Signer
	Redis             *redis.Client
	Providers         map[string]OAuthProvider
	StateHMACSecret   []byte
	AccessTTL         time.Duration
	RefreshTTLHours   int
}

// NewOAuthService returns a new OAuthService.
func NewOAuthService(cfg *OAuthServiceConfig) *OAuthService {
	return &OAuthService{
		users:         cfg.UserStore,
		identities:    cfg.AuthIdentityStore,
		refreshTokens: cfg.RefreshTokenStore,
		signer:        cfg.Signer,
		redisClient:   cfg.Redis,
		providers:     cfg.Providers,
		stateHMACKey:  cfg.StateHMACSecret,
		accessTTL:     cfg.AccessTTL,
		refreshTTLH:   cfg.RefreshTTLHours,
	}
}

// OAuthStartResult is returned by Start.
type OAuthStartResult struct {
	AuthorizeURL string
}

// Start generates a state + PKCE verifier, stores them in Redis, and returns
// the provider authorization URL. The state is HMAC-signed to prevent CSRF.
func (s *OAuthService) Start(ctx context.Context, provider string) (*OAuthStartResult, error) {
	if !domain.ValidOAuthProviders[provider] {
		return nil, domain.ErrOAuthProviderUnknown
	}

	p, ok := s.providers[provider]
	if !ok {
		return nil, domain.ErrOAuthProviderUnknown
	}

	rawState, err := randBase64URL32()
	if err != nil {
		return nil, fmt.Errorf("generate state: %w", err)
	}

	codeVerifier, err := randBase64URL32()
	if err != nil {
		return nil, fmt.Errorf("generate verifier: %w", err)
	}

	// Sign the state value so the callback can verify it was issued by us.
	signedState := s.signState(rawState)

	entry := oauthStateEntry{CodeVerifier: codeVerifier, Provider: provider}

	data, err := json.Marshal(entry)
	if err != nil {
		return nil, fmt.Errorf("marshal state entry: %w", err)
	}

	key := oauthStateKeyPrefix + rawState

	if err := s.redisClient.Set(ctx, key, data, oauthStateTTL).Err(); err != nil {
		return nil, fmt.Errorf("store oauth state: %w", err)
	}

	// PKCE S256: codeChallenge = BASE64URL(SHA256(codeVerifier))
	codeChallenge := pkceChallenge(codeVerifier)
	// Providers are pre-configured with their redirect URI; pass empty string so
	// provider.AuthorizeURL uses the redirect_uri baked into the ProviderConfig.
	authURL := p.AuthorizeURL(signedState, codeChallenge, "")

	return &OAuthStartResult{AuthorizeURL: authURL}, nil
}

// CallbackOutcome enumerates the possible outcomes of a HandleCallback call.
type CallbackOutcome int

const (
	// CallbackLogin means an existing auth_identity was found; a one-time code was issued.
	CallbackLogin CallbackOutcome = iota
	// CallbackNewUser means a new user was created; a one-time code was issued.
	CallbackNewUser
	// CallbackEmailCollision means the provider email matches an existing user but Design A
	// forbids auto-linking. No user was created/logged in.
	CallbackEmailCollision
	// CallbackBindSuccess means a bind flow completed successfully.
	CallbackBindSuccess
)

// CallbackResult is returned by HandleCallback.
type CallbackResult struct {
	Outcome     CallbackOutcome
	OneTimeCode string // non-empty for CallbackLogin and CallbackNewUser
}

// HandleCallback is the unified callback handler for both login and bind flows.
// It reads the Redis state entry to determine whether it is a login or bind callback,
// then delegates to the appropriate internal logic.
func (s *OAuthService) HandleCallback(ctx context.Context, provider, code, signedState string) (*CallbackResult, error) {
	if !domain.ValidOAuthProviders[provider] {
		return nil, domain.ErrOAuthProviderUnknown
	}

	p, ok := s.providers[provider]
	if !ok {
		return nil, domain.ErrOAuthProviderUnknown
	}

	// Verify HMAC signature on state.
	rawState, valid := s.verifyState(signedState)
	if !valid {
		return nil, domain.ErrOAuthStateInvalid
	}

	// Consume the Redis state entry (single-use).
	key := oauthStateKeyPrefix + rawState
	data, err := s.redisClient.GetDel(ctx, key).Bytes()
	if err != nil {
		return nil, domain.ErrOAuthStateInvalid
	}

	var entry oauthStateEntry

	if err := json.Unmarshal(data, &entry); err != nil {
		return nil, domain.ErrOAuthStateInvalid
	}

	// Guard: state entry must be for the same provider as the callback route.
	if entry.Provider != provider {
		return nil, domain.ErrOAuthStateInvalid
	}

	// Route to bind or login flow based on ForBind presence.
	if entry.ForBind != "" {
		return s.handleBindCallback(ctx, p, provider, code, entry)
	}

	return s.handleLoginCallback(ctx, p, provider, code, entry)
}

// handleLoginCallback runs the Design-A login logic after state validation.
func (s *OAuthService) handleLoginCallback(
	ctx context.Context,
	p OAuthProvider,
	provider, code string,
	entry oauthStateEntry,
) (*CallbackResult, error) {
	// Exchange code → access token.
	accessToken, err := p.ExchangeCode(ctx, code, entry.CodeVerifier, "")
	if err != nil {
		slog.Warn("oauth exchange failed", "provider", provider, "err", err)
		return nil, fmt.Errorf("%w: %w", domain.ErrOAuthExchangeFailed, err)
	}

	// Fetch identity from provider.
	identity, err := p.FetchIdentity(ctx, accessToken)
	if err != nil {
		slog.Warn("oauth fetch identity failed", "provider", provider, "err", err)
		return nil, fmt.Errorf("%w: %w", domain.ErrOAuthExchangeFailed, err)
	}

	return s.resolveLoginIdentity(ctx, provider, identity)
}

// resolveLoginIdentity implements Design-A linking logic.
// Extracted from handleLoginCallback to keep cyclomatic complexity within bounds.
func (s *OAuthService) resolveLoginIdentity(
	ctx context.Context,
	provider string,
	identity *oauth.Identity,
) (*CallbackResult, error) {
	// Case 1: existing identity row → known user → issue one-time code.
	existing, err := s.identities.GetByProvider(ctx, provider, identity.ProviderSubject)
	if err != nil && !errors.Is(err, domain.ErrNotFound) {
		return nil, fmt.Errorf("get identity: %w", err)
	}

	if existing != nil {
		u, userErr := s.users.GetByID(ctx, existing.UserID)
		if userErr != nil {
			return nil, fmt.Errorf("resolve user: %w", userErr)
		}

		if u.Status == domain.UserStatusSuspended {
			return nil, domain.ErrAccountSuspended
		}

		otCode, codeErr := s.issueOneTimeCode(ctx, u.ID)
		if codeErr != nil {
			return nil, codeErr
		}

		return &CallbackResult{Outcome: CallbackLogin, OneTimeCode: otCode}, nil
	}

	// Case 2: no identity row. Check for email collision (Design A: NEVER auto-link).
	// Only check when the email is present AND the provider asserts it is verified —
	// an unverified provider email must not block registration (denial-of-registration risk).
	if identity.Email != "" && identity.EmailVerified {
		_, emailErr := s.users.GetByEmail(ctx, strings.ToLower(strings.TrimSpace(identity.Email)))
		if emailErr == nil {
			return &CallbackResult{Outcome: CallbackEmailCollision}, nil
		}

		if !errors.Is(emailErr, domain.ErrNotFound) {
			return nil, fmt.Errorf("check email collision: %w", emailErr)
		}
	}

	// Case 3: no identity, no collision → create new PENDING_VERIFICATION user.
	return s.createOAuthUser(ctx, provider, identity)
}

// createOAuthUser creates a new OAuth-only user and auth_identity row,
// then issues a one-time code.
//
// No-email providers (LINE without email permission): a synthetic unique email of the
// form "oauth+<providerSubject>@noemail.<provider>.invalid" is used so the NOT-NULL
// UNIQUE(email) constraint is satisfied. This address is never used for communication
// (it resolves to the RFC-2606 .invalid TLD) and EmailVerified is always false.
func (s *OAuthService) createOAuthUser(
	ctx context.Context,
	provider string,
	identity *oauth.Identity,
) (*CallbackResult, error) {
	now := time.Now().UTC()
	userID := uuid.New()

	// Determine the canonical email stored on the users row.
	// When the provider supplies no email we synthesize a unique placeholder so the
	// NOT NULL UNIQUE citext column is satisfied. The .invalid TLD (RFC 2606) prevents
	// any accidental delivery.
	var email string
	var emailVerified bool
	var displayName string

	if identity.Email != "" {
		email = strings.ToLower(strings.TrimSpace(identity.Email))
		emailVerified = identity.EmailVerified
		displayName = email
	} else {
		email = "oauth+" + identity.ProviderSubject + "@noemail." + provider + ".invalid"
		emailVerified = false
		displayName = identity.ProviderSubject
	}

	u := &domain.User{
		ID:            userID,
		Email:         email,
		PasswordHash:  nil, // OAuth-only, no password
		DisplayName:   displayName,
		AccountType:   domain.AccountTypePersonal,
		KYCTier:       0,
		Status:        domain.UserStatusPendingVerification,
		EmailVerified: emailVerified,
		TokenVersion:  0,
		CreatedAt:     now,
		UpdatedAt:     now,
	}

	if err := s.users.Create(ctx, u); err != nil {
		return nil, fmt.Errorf("create oauth user: %w", err)
	}

	var emailPtr *string
	if identity.Email != "" {
		v := identity.Email
		emailPtr = &v
	}

	ai := &domain.AuthIdentity{
		ID:              uuid.New(),
		Provider:        provider,
		ProviderSubject: identity.ProviderSubject,
		UserID:          userID,
		Email:           emailPtr,
		LinkedAt:        now,
	}

	if err := s.identities.Create(ctx, ai); err != nil {
		return nil, fmt.Errorf("create auth_identity: %w", err)
	}

	otCode, err := s.issueOneTimeCode(ctx, userID)
	if err != nil {
		return nil, err
	}

	return &CallbackResult{Outcome: CallbackNewUser, OneTimeCode: otCode}, nil
}

// handleBindCallback runs the bind flow after state validation.
func (s *OAuthService) handleBindCallback(
	ctx context.Context,
	p OAuthProvider,
	provider, code string,
	entry oauthStateEntry,
) (*CallbackResult, error) {
	bindUserID, err := uuid.Parse(entry.ForBind)
	if err != nil {
		return nil, domain.ErrOAuthStateInvalid
	}

	// Verify the bind target user still exists (e.g. not soft-deleted between
	// BindStart and the callback arriving).
	if _, err := s.users.GetByID(ctx, bindUserID); err != nil {
		return nil, fmt.Errorf("bind target user: %w", err)
	}

	accessToken, err := p.ExchangeCode(ctx, code, entry.CodeVerifier, "")
	if err != nil {
		slog.Warn("oauth bind exchange failed", "provider", provider, "err", err)
		return nil, fmt.Errorf("%w: %w", domain.ErrOAuthExchangeFailed, err)
	}

	identity, err := p.FetchIdentity(ctx, accessToken)
	if err != nil {
		slog.Warn("oauth bind fetch identity failed", "provider", provider, "err", err)
		return nil, fmt.Errorf("%w: %w", domain.ErrOAuthExchangeFailed, err)
	}

	// Reject if (provider, provider_subject) already bound to ANY user.
	existing, err := s.identities.GetByProvider(ctx, provider, identity.ProviderSubject)
	if err != nil && !errors.Is(err, domain.ErrNotFound) {
		return nil, fmt.Errorf("check existing identity: %w", err)
	}

	if existing != nil {
		return nil, domain.ErrIdentityAlreadyBound
	}

	now := time.Now().UTC()

	var emailPtr *string
	if identity.Email != "" {
		v := identity.Email
		emailPtr = &v
	}

	ai := &domain.AuthIdentity{
		ID:              uuid.New(),
		Provider:        provider,
		ProviderSubject: identity.ProviderSubject,
		UserID:          bindUserID,
		Email:           emailPtr,
		LinkedAt:        now,
	}

	if createErr := s.identities.Create(ctx, ai); createErr != nil {
		return nil, createErr
	}

	slog.Info("oauth.bind_success", "userId", bindUserID, "provider", provider)

	return &CallbackResult{Outcome: CallbackBindSuccess}, nil
}

// OAuthTokenPair mirrors service.TokenPair — kept here to avoid import cycles.
type OAuthTokenPair struct {
	AccessToken  string
	RefreshToken string
	ExpiresIn    int
}

// Exchange consumes a one-time login code and issues a full token pair.
func (s *OAuthService) Exchange(ctx context.Context, oneTimeCode string) (*OAuthTokenPair, error) {
	if strings.TrimSpace(oneTimeCode) == "" {
		return nil, domain.ErrOAuthOneTimeCodeInvalid
	}

	key := oauthCodeKeyPrefix + oneTimeCode
	data, err := s.redisClient.GetDel(ctx, key).Bytes()
	if err != nil {
		return nil, domain.ErrOAuthOneTimeCodeInvalid
	}

	var entry oauthCodeEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		return nil, domain.ErrOAuthOneTimeCodeInvalid
	}

	userID, parseErr := uuid.Parse(entry.UserID)
	if parseErr != nil {
		return nil, domain.ErrOAuthOneTimeCodeInvalid
	}

	u, err := s.users.GetByID(ctx, userID)
	if err != nil {
		return nil, domain.ErrOAuthOneTimeCodeInvalid
	}

	if u.Status == domain.UserStatusSuspended {
		return nil, domain.ErrAccountSuspended
	}

	return s.issueTokens(ctx, u)
}

// BindStartResult is returned by BindStart.
type BindStartResult struct {
	AuthorizeURL string
}

// BindStart initiates an OAuth flow for binding a new provider to an existing user.
// The authenticatedUserID is embedded in the state Redis entry so the callback can
// identify the binding target.
func (s *OAuthService) BindStart(ctx context.Context, provider string, authenticatedUserID uuid.UUID) (*BindStartResult, error) {
	if !domain.ValidOAuthProviders[provider] {
		return nil, domain.ErrOAuthProviderUnknown
	}

	p, ok := s.providers[provider]
	if !ok {
		return nil, domain.ErrOAuthProviderUnknown
	}

	rawState, err := randBase64URL32()
	if err != nil {
		return nil, fmt.Errorf("generate bind state: %w", err)
	}

	codeVerifier, err := randBase64URL32()
	if err != nil {
		return nil, fmt.Errorf("generate bind verifier: %w", err)
	}

	signedState := s.signState(rawState)

	entry := oauthStateEntry{
		CodeVerifier: codeVerifier,
		Provider:     provider,
		ForBind:      authenticatedUserID.String(),
	}

	data, err := json.Marshal(entry)
	if err != nil {
		return nil, fmt.Errorf("marshal bind state: %w", err)
	}

	key := oauthStateKeyPrefix + rawState

	if err := s.redisClient.Set(ctx, key, data, oauthStateTTL).Err(); err != nil {
		return nil, fmt.Errorf("store bind state: %w", err)
	}

	codeChallenge := pkceChallenge(codeVerifier)
	// Pass empty redirectURI: provider is pre-configured with the canonical redirect URI.
	authURL := p.AuthorizeURL(signedState, codeChallenge, "")

	return &BindStartResult{AuthorizeURL: authURL}, nil
}

// Unbind removes an auth_identity for the authenticated user.
// It rejects if doing so would leave the user with no login method.
func (s *OAuthService) Unbind(ctx context.Context, authenticatedUserID uuid.UUID, provider string) error {
	if !domain.ValidOAuthProviders[provider] {
		return domain.ErrOAuthProviderUnknown
	}

	u, err := s.users.GetByID(ctx, authenticatedUserID)
	if err != nil {
		return err
	}

	allIdentities, err := s.identities.ListByUserID(ctx, authenticatedUserID)
	if err != nil {
		return fmt.Errorf("list identities: %w", err)
	}

	// Guard: removing this identity must not leave user with no login method.
	// A login method is: password_hash IS NOT NULL or an identity for a different provider.
	remainingIdentities := 0

	for _, ai := range allIdentities {
		if ai.Provider != provider {
			remainingIdentities++
		}
	}

	hasPassword := u.PasswordHash != nil

	if remainingIdentities == 0 && !hasPassword {
		return domain.ErrLastLoginMethod
	}

	return s.identities.DeleteByUserAndProvider(ctx, authenticatedUserID, provider)
}

// IdentityItem is a single bound social identity returned by ListIdentities.
type IdentityItem struct {
	Provider string
	Email    *string
	LinkedAt time.Time
}

// ListIdentitiesResult is returned by ListIdentities.
type ListIdentitiesResult struct {
	Identities  []*IdentityItem
	HasPassword bool
}

// ListIdentities returns all bound OAuth identities for the authenticated user and
// whether the user also has a password (used by the frontend Settings page).
func (s *OAuthService) ListIdentities(ctx context.Context, authenticatedUserID uuid.UUID) (*ListIdentitiesResult, error) {
	u, err := s.users.GetByID(ctx, authenticatedUserID)
	if err != nil {
		return nil, fmt.Errorf("get user: %w", err)
	}

	ais, err := s.identities.ListByUserID(ctx, authenticatedUserID)
	if err != nil {
		return nil, fmt.Errorf("list identities: %w", err)
	}

	items := make([]*IdentityItem, 0, len(ais))
	for _, ai := range ais {
		items = append(items, &IdentityItem{
			Provider: ai.Provider,
			Email:    ai.Email,
			LinkedAt: ai.LinkedAt,
		})
	}

	return &ListIdentitiesResult{
		Identities:  items,
		HasPassword: u.PasswordHash != nil,
	}, nil
}

// issueOneTimeCode creates a short-lived Redis entry and returns the raw code.
func (s *OAuthService) issueOneTimeCode(ctx context.Context, userID uuid.UUID) (string, error) {
	code, err := randBase64URL32()
	if err != nil {
		return "", fmt.Errorf("generate one-time code: %w", err)
	}

	entry := oauthCodeEntry{UserID: userID.String()}

	data, err := json.Marshal(entry)
	if err != nil {
		return "", fmt.Errorf("marshal code entry: %w", err)
	}

	key := oauthCodeKeyPrefix + code

	if err := s.redisClient.Set(ctx, key, data, oauthOneTimeTTL).Err(); err != nil {
		return "", fmt.Errorf("store one-time code: %w", err)
	}

	return code, nil
}

// issueTokens issues a new token pair for the given user
// (mirrors auth_service.issueTokenPair logic).
func (s *OAuthService) issueTokens(ctx context.Context, u *domain.User) (*OAuthTokenPair, error) {
	accessToken, err := s.signer.Issue(u.ID.String(), u.AccountType, u.KYCTier, u.TokenVersion, u.EmailVerified)
	if err != nil {
		return nil, err
	}

	tok, err := refresh.Generate()
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	familyID := uuid.New()

	rt := &domain.RefreshToken{
		ID:           tok.ID,
		UserID:       u.ID,
		FamilyID:     familyID,
		TokenHash:    tok.Hash,
		ExpiresAt:    now.Add(time.Duration(s.refreshTTLH) * time.Hour),
		CreatedAt:    now,
		TokenVersion: u.TokenVersion,
	}

	if err := s.refreshTokens.Create(ctx, rt); err != nil {
		return nil, err
	}

	return &OAuthTokenPair{
		AccessToken:  accessToken,
		RefreshToken: tok.Raw,
		ExpiresIn:    int(s.accessTTL.Seconds()),
	}, nil
}

// signState appends an HMAC-SHA256 signature to the raw state value.
// Format: rawState.BASE64URL(HMAC(rawState)).
func (s *OAuthService) signState(rawState string) string {
	mac := hmac.New(sha256.New, s.stateHMACKey)
	mac.Write([]byte(rawState))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	return rawState + "." + sig
}

// verifyState splits a signed state and verifies the HMAC.
// Returns (rawState, true) on success, ("", false) otherwise.
func (s *OAuthService) verifyState(signed string) (string, bool) {
	idx := strings.LastIndex(signed, ".")
	if idx < 0 {
		return "", false
	}

	raw := signed[:idx]
	gotSig := signed[idx+1:]

	mac := hmac.New(sha256.New, s.stateHMACKey)
	mac.Write([]byte(raw))
	expectedSig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	if !hmac.Equal([]byte(gotSig), []byte(expectedSig)) {
		return "", false
	}

	return raw, true
}

// randBase64URL32 returns 32 random bytes as a base64url-encoded string (no padding).
// Used for state, PKCE verifier, and one-time code generation.
func randBase64URL32() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(b), nil
}

// pkceChallenge computes the S256 PKCE code challenge for a given verifier.
func pkceChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))

	return base64.RawURLEncoding.EncodeToString(sum[:])
}
