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
	"sync"
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

// oauthRegTokenKeyPrefix is the Redis key prefix for no-email registration pending tokens.
const oauthRegTokenKeyPrefix = "oauth:reg:" //nolint:gosec // G101: key prefix string, not a credential value

// oauthRegTokenTTL is how long a no-email registration token remains valid.
const oauthRegTokenTTL = 15 * time.Minute

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

// oauthRegTokenEntry is serialized into Redis when a no-email provider callback
// (e.g. LINE without email scope) needs to collect a real email before creating
// the user. The token is single-use and expires after oauthRegTokenTTL.
type oauthRegTokenEntry struct {
	Provider        string `json:"p"`
	ProviderSubject string `json:"s"`
	DisplayName     string `json:"d"`
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
	verifications store.EmailVerificationTokenStore // for no-email register flow
	signer        *jwt.Signer
	redisClient   *redis.Client
	providers     map[string]OAuthProvider
	mailer        Mailer // for verification email dispatch in Register
	// stateHMACKey signs and verifies the state parameter to prevent CSRF.
	stateHMACKey []byte
	accessTTL    time.Duration
	refreshTTLH  int
	// sendWG tracks in-flight detached email goroutines (mirrors AuthService pattern).
	sendWG sync.WaitGroup
}

// OAuthServiceConfig bundles the dependencies for NewOAuthService.
type OAuthServiceConfig struct {
	UserStore         store.UserStore
	AuthIdentityStore store.AuthIdentityStore
	RefreshTokenStore store.RefreshTokenStore
	// VerificationStore and Mailer are required for the no-email register endpoint
	// (POST /v1/auth/oauth/register). When nil the Register method returns ErrNotFound.
	VerificationStore store.EmailVerificationTokenStore
	Mailer            Mailer
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
		verifications: cfg.VerificationStore,
		signer:        cfg.Signer,
		redisClient:   cfg.Redis,
		providers:     cfg.Providers,
		mailer:        cfg.Mailer,
		stateHMACKey:  cfg.StateHMACSecret,
		accessTTL:     cfg.AccessTTL,
		refreshTTLH:   cfg.RefreshTTLHours,
	}
}

// WaitForPendingSends blocks until all in-flight detached verification-email goroutines
// complete. Mirrors AuthService.WaitForPendingSends; called at graceful shutdown.
func (s *OAuthService) WaitForPendingSends() {
	s.sendWG.Wait()
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
	// CallbackNeedsRegistration means the provider did not supply an email address
	// (e.g. LINE without email scope). A short-lived registration token was stored in
	// Redis. The frontend must collect a real email via POST /v1/auth/oauth/register.
	// No user is created at this stage; RegToken carries the opaque token.
	CallbackNeedsRegistration
)

// CallbackResult is returned by HandleCallback.
type CallbackResult struct {
	Outcome     CallbackOutcome
	OneTimeCode string // non-empty for CallbackLogin and CallbackNewUser
	RegToken    string // non-empty for CallbackNeedsRegistration
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

	// Case 3: provider did not supply an email (e.g. LINE without email scope).
	// Do NOT auto-create a placeholder account — redirect the frontend to collect a
	// real email address via POST /v1/auth/oauth/register.
	if identity.Email == "" {
		return s.issueRegToken(ctx, provider, identity)
	}

	// Case 4: no identity, email present, no collision → create new PENDING_VERIFICATION user.
	return s.createOAuthUser(ctx, provider, identity, "")
}

// issueRegToken stores a short-lived registration-pending token in Redis and returns
// a CallbackNeedsRegistration result. Called when the provider does not supply an email.
func (s *OAuthService) issueRegToken(
	ctx context.Context,
	provider string,
	identity *oauth.Identity,
) (*CallbackResult, error) {
	regToken, err := randBase64URL32()
	if err != nil {
		return nil, fmt.Errorf("generate reg token: %w", err)
	}

	// Use providerSubject as the display name seed — the frontend can update it later.
	// oauth.Identity has no separate DisplayName field.
	displayName := identity.ProviderSubject

	entry := oauthRegTokenEntry{
		Provider:        provider,
		ProviderSubject: identity.ProviderSubject,
		DisplayName:     displayName,
	}

	data, err := json.Marshal(entry)
	if err != nil {
		return nil, fmt.Errorf("marshal reg token entry: %w", err)
	}

	key := oauthRegTokenKeyPrefix + regToken

	if err := s.redisClient.Set(ctx, key, data, oauthRegTokenTTL).Err(); err != nil {
		return nil, fmt.Errorf("store reg token: %w", err)
	}

	return &CallbackResult{Outcome: CallbackNeedsRegistration, RegToken: regToken}, nil
}

// createOAuthUser creates a new OAuth-only user and auth_identity row for a provider
// that DID supply an email address, then issues a one-time code.
// INVARIANT: identity.Email MUST NOT be empty — callers MUST check before calling.
// displayNameOverride, when non-empty, is used instead of the email as the display name
// (used by the Register flow where the provider subject is a better initial name).
func (s *OAuthService) createOAuthUser(
	ctx context.Context,
	provider string,
	identity *oauth.Identity,
	displayNameOverride string,
) (*CallbackResult, error) {
	now := time.Now().UTC()
	userID := uuid.New()

	// identity.Email is guaranteed non-empty by the caller (resolveLoginIdentity case 4
	// and Register). Enforce defensively.
	if identity.Email == "" {
		return nil, fmt.Errorf("createOAuthUser called with empty email for provider %s subject %s", provider, identity.ProviderSubject)
	}

	email := strings.ToLower(strings.TrimSpace(identity.Email))
	emailVerified := identity.EmailVerified

	displayName := email
	if displayNameOverride != "" {
		displayName = displayNameOverride
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

	// email is non-empty (enforced above); store it as the linked identity email.
	emailCopy := identity.Email
	ai := &domain.AuthIdentity{
		ID:              uuid.New(),
		Provider:        provider,
		ProviderSubject: identity.ProviderSubject,
		UserID:          userID,
		Email:           &emailCopy,
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

// RegisterOutcome enumerates the possible outcomes of a Register call.
type RegisterOutcome int

const (
	// RegisterNewUser means a new user was created and a one-time login code was issued.
	RegisterNewUser RegisterOutcome = iota
	// RegisterEmailCollision means the supplied email already belongs to a non-deleted
	// user. Design A: NEVER auto-link. No user was created.
	RegisterEmailCollision
)

// RegisterResult is returned by Register.
type RegisterResult struct {
	Outcome     RegisterOutcome
	OneTimeCode string // non-empty for RegisterNewUser
}

// ErrOAuthRegTokenInvalid is returned by Register when the regToken is missing,
// expired, or already consumed (single-use guard).
var ErrOAuthRegTokenInvalid = errors.New("oauth registration token invalid or expired")

// Register consumes a no-email registration token (issued by issueRegToken during a
// no-email provider callback) and creates a new user with the caller-supplied email.
//
// Flow:
//  1. GetDel regToken from Redis (single-use). Invalid/expired → ErrOAuthRegTokenInvalid.
//  2. Validate + normalize email.
//  3. Email collision check (Design A): existing non-deleted user → RegisterEmailCollision.
//  4. Create PENDING_VERIFICATION user with real email + linked identity.
//  5. Create email-verification token, dispatch verification email (detached goroutine).
//  6. Issue a one-time login code → user is logged in as PENDING_VERIFICATION.
func (s *OAuthService) Register(ctx context.Context, regToken, email string) (*RegisterResult, error) {
	// 1. Consume the registration token (single-use).
	key := oauthRegTokenKeyPrefix + regToken
	data, err := s.redisClient.GetDel(ctx, key).Bytes()
	if err != nil {
		return nil, ErrOAuthRegTokenInvalid
	}

	var entry oauthRegTokenEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		return nil, ErrOAuthRegTokenInvalid
	}

	// 2. Validate + normalize email.
	normalized := strings.ToLower(strings.TrimSpace(email))
	if normalized == "" {
		return nil, domain.ErrValidation
	}

	// 3. Email collision check (Design A — NEVER auto-link).
	_, emailErr := s.users.GetByEmail(ctx, normalized)
	if emailErr == nil {
		// User with this email exists.
		return &RegisterResult{Outcome: RegisterEmailCollision}, nil
	}

	if !errors.Is(emailErr, domain.ErrNotFound) {
		return nil, fmt.Errorf("check email collision: %w", emailErr)
	}

	// 4. Create new user + auth_identity.
	// Use normalized email as identity.Email; pass the stored displayName override so
	// the user row gets a meaningful name (provider subject) rather than just the email.
	synthetic := &oauth.Identity{
		ProviderSubject: entry.ProviderSubject,
		Email:           normalized,
		EmailVerified:   false, // email not yet verified — user must click the link
	}

	result, err := s.createOAuthUser(ctx, entry.Provider, synthetic, entry.DisplayName)
	if err != nil {
		return nil, err
	}

	// 5. Create verification token + dispatch email (detached, same pattern as AuthService).
	if s.verifications != nil {
		rawToken, tokenHash, vtErr := newVerificationToken()
		if vtErr != nil {
			return nil, fmt.Errorf("create verification token: %w", vtErr)
		}

		now := time.Now().UTC()
		vt := &domain.EmailVerificationToken{
			ID:        uuid.New(),
			UserID:    uuid.Nil, // will be set after we can obtain the user ID
			TokenHash: tokenHash,
			ExpiresAt: now.Add(verificationTokenTTL),
			CreatedAt: now,
		}

		// Obtain the just-created user ID via the store (needed for the token).
		// createOAuthUser already called users.Create; we need the ID back.
		// Since we pass identity.Email == normalized, GetByEmail will retrieve it.
		createdUser, getUserErr := s.users.GetByEmail(ctx, normalized)
		if getUserErr != nil {
			return nil, fmt.Errorf("get created user: %w", getUserErr)
		}

		vt.UserID = createdUser.ID

		if createErr := s.verifications.Create(ctx, vt); createErr != nil {
			return nil, fmt.Errorf("persist verification token: %w", createErr)
		}

		//nolint:contextcheck // intentional detach: goroutine MUST NOT inherit the request ctx (canceled on handler return) — backend-security-design §5
		s.dispatchVerificationEmail(normalized, rawToken)
	}

	return &RegisterResult{Outcome: RegisterNewUser, OneTimeCode: result.OneTimeCode}, nil
}

// dispatchVerificationEmail sends the verification email on a detached goroutine.
// MUST NOT inherit request context (canceled when handler returns) — §5 backend-security-design.
// Uses context.Background() explicitly so the send is not canceled when the request ends.
func (s *OAuthService) dispatchVerificationEmail(email, rawToken string) {
	if s.mailer == nil {
		return
	}

	s.sendWG.Add(1)

	go func() {
		defer s.sendWG.Done()
		if err := s.mailer.SendVerification(context.Background(), email, rawToken); err != nil {
			slog.Warn("oauth register: verification email send failed", "email", email, "err", err)
		}
	}()
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
