package service_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/CoverOnes/user/internal/auth/jwt"
	"github.com/CoverOnes/user/internal/domain"
	"github.com/CoverOnes/user/internal/oauth"
	"github.com/CoverOnes/user/internal/service"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	tcredis "github.com/testcontainers/testcontainers-go/modules/redis"
)

// oauthTestHMACKey is a 32-byte HMAC secret for unit tests.
var oauthTestHMACKey = []byte("test-hmac-secret-oauth-unit-tests")

// --- fake OAuthProvider ---

// fakeOAuthProvider is a controllable OAuthProvider stub.
// Each call field is overridable per test case.
type fakeOAuthProvider struct {
	authorizeURL  string
	exchangeErr   error
	exchangeToken string
	fetchIdentity *oauth.Identity
	fetchErr      error
}

func (f *fakeOAuthProvider) AuthorizeURL(state, _, _ string) string {
	if f.authorizeURL != "" {
		return f.authorizeURL
	}
	return "https://provider.example.com/authorize?state=" + state
}

func (f *fakeOAuthProvider) ExchangeCode(_ context.Context, _, _, _ string) (string, error) {
	if f.exchangeErr != nil {
		return "", f.exchangeErr
	}
	if f.exchangeToken != "" {
		return f.exchangeToken, nil
	}
	return "fake-access-token", nil
}

func (f *fakeOAuthProvider) FetchIdentity(_ context.Context, _ string) (*oauth.Identity, error) {
	if f.fetchErr != nil {
		return nil, f.fetchErr
	}
	if f.fetchIdentity != nil {
		return f.fetchIdentity, nil
	}
	return &oauth.Identity{ProviderSubject: "sub123", Email: "user@example.com", EmailVerified: true}, nil
}

// --- test helpers ---

// startOAuthTestRedis spins up a real Redis container and returns a connected client.
func startOAuthTestRedis(t *testing.T) *redis.Client {
	t.Helper()

	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ctx := context.Background()
	ctr, err := tcredis.Run(ctx, "redis:7-alpine")
	require.NoError(t, err)

	t.Cleanup(func() {
		if termErr := ctr.Terminate(ctx); termErr != nil {
			t.Logf("terminate redis container: %v", termErr)
		}
	})

	addr, err := ctr.ConnectionString(ctx)
	require.NoError(t, err)

	opts, err := redis.ParseURL(addr)
	require.NoError(t, err)

	rdb := redis.NewClient(opts)
	t.Cleanup(func() { _ = rdb.Close() })

	return rdb
}

// newOAuthSvc builds a minimal OAuthService backed by fakes + real Redis.
func newOAuthSvc(
	t *testing.T,
	users *fakeUserStore,
	identities *fakeAuthIdentityStore,
	rts *fakeRefreshTokenStore,
	providers map[string]service.OAuthProvider,
	rdb *redis.Client,
) *service.OAuthService {
	t.Helper()

	signer, err := jwt.NewEphemeralSigner(10 * time.Minute)
	require.NoError(t, err)

	return service.NewOAuthService(&service.OAuthServiceConfig{
		UserStore:         users,
		AuthIdentityStore: identities,
		RefreshTokenStore: rts,
		Signer:            signer,
		Redis:             rdb,
		Providers:         providers,
		StateHMACSecret:   oauthTestHMACKey,
		AccessTTL:         10 * time.Minute,
		RefreshTTLHours:   24,
	})
}

// seedOAuthUser creates an active user (no password) in the fake store.
// t may be nil when called from setup funcs that don't have a testing.T.
func seedOAuthUser(_ *testing.T, users *fakeUserStore) *domain.User {
	now := time.Now().UTC()
	u := &domain.User{
		ID:            uuid.New(),
		Email:         "oauthuser@example.com",
		PasswordHash:  nil,
		DisplayName:   "OAuth User",
		AccountType:   domain.AccountTypePersonal,
		Status:        domain.UserStatusActive,
		EmailVerified: true,
		TokenVersion:  0,
		CreatedAt:     now,
		UpdatedAt:     now,
	}
	users.byID[u.ID] = u
	users.byEmail[u.Email] = u

	return u
}

// seedAuthIdentity creates an auth_identity for user in the fake identities store.
// t may be nil when called from setup funcs that don't have a testing.T.
func seedAuthIdentity(_ *testing.T, identities *fakeAuthIdentityStore, userID uuid.UUID, provider, subject string) {
	now := time.Now().UTC()
	ai := &domain.AuthIdentity{
		ID:              uuid.New(),
		Provider:        provider,
		ProviderSubject: subject,
		UserID:          userID,
		LinkedAt:        now,
	}
	key := provider + ":" + subject
	identities.byProviderSubject[key] = ai
	identities.byUserID[userID.String()] = append(identities.byUserID[userID.String()], ai)
}

// issueSignedState calls Start on the OAuthService for the google provider and
// extracts the signed state from the authorization URL.
// The returned string is the signed state as produced by signState.
func issueSignedState(t *testing.T, svc *service.OAuthService) string {
	t.Helper()

	ctx := context.Background()
	res, err := svc.Start(ctx, "google")
	require.NoError(t, err)

	// AuthorizeURL has format "...?...&state=<signed>" — extract state param.
	u := res.AuthorizeURL
	const stateParam = "state="

	idx := -1
	for i := 0; i+len(stateParam) <= len(u); i++ {
		if u[i:i+len(stateParam)] == stateParam {
			idx = i + len(stateParam)
			break
		}
	}

	require.True(t, idx > 0, "state param not found in AuthorizeURL: %s", u)

	// Find end of state value (stop at & or end).
	state := u[idx:]
	for i, ch := range state {
		if ch == '&' {
			state = state[:i]
			break
		}
	}

	require.NotEmpty(t, state)

	return state
}

// issueSignedStateForProvider is like issueSignedState but allows specifying the provider.
func issueSignedStateForProvider(t *testing.T, svc *service.OAuthService, provider string) string {
	t.Helper()

	ctx := context.Background()
	res, err := svc.Start(ctx, provider)
	require.NoError(t, err)

	u := res.AuthorizeURL
	const stateParam = "state="

	idx := -1
	for i := 0; i+len(stateParam) <= len(u); i++ {
		if u[i:i+len(stateParam)] == stateParam {
			idx = i + len(stateParam)
			break
		}
	}

	require.True(t, idx > 0, "state param not found in AuthorizeURL: %s", u)

	state := u[idx:]
	for i, ch := range state {
		if ch == '&' {
			state = state[:i]
			break
		}
	}

	require.NotEmpty(t, state)

	return state
}

// --- TestOAuthService_Start ---

func TestOAuthService_Start(t *testing.T) {
	rdb := startOAuthTestRedis(t)

	tests := []struct {
		name     string
		provider string
		wantErr  error
		wantURL  bool // expect a URL in the result
	}{
		{
			name:     "google provider returns authorize URL",
			provider: "google",
			wantURL:  true,
		},
		{
			name:     "line provider returns authorize URL",
			provider: "line",
			wantURL:  true,
		},
		{
			name:     "unknown provider returns ErrOAuthProviderUnknown",
			provider: "facebook",
			wantErr:  domain.ErrOAuthProviderUnknown,
		},
		{
			name:     "empty provider returns ErrOAuthProviderUnknown",
			provider: "",
			wantErr:  domain.ErrOAuthProviderUnknown,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			svc := newOAuthSvc(
				t,
				newFakeUserStore(),
				newFakeAuthIdentityStore(),
				newFakeRefreshTokenStore(),
				map[string]service.OAuthProvider{
					"google": &fakeOAuthProvider{authorizeURL: "https://google.example.com/auth"},
					"line":   &fakeOAuthProvider{authorizeURL: "https://line.example.com/auth"},
				},
				rdb,
			)

			res, err := svc.Start(context.Background(), tc.provider)

			if tc.wantErr != nil {
				require.Error(t, err)
				assert.ErrorIs(t, err, tc.wantErr)
				assert.Nil(t, res)
				return
			}

			require.NoError(t, err)

			if tc.wantURL {
				assert.NotEmpty(t, res.AuthorizeURL)
			}
		})
	}
}

// --- TestOAuthService_HandleCallback_Login ---

func TestOAuthService_HandleCallback_Login(t *testing.T) {
	const provider = "google"

	tests := []struct {
		name        string
		setup       func(users *fakeUserStore, identities *fakeAuthIdentityStore) (*fakeOAuthProvider, *fakeUserStore, *fakeAuthIdentityStore)
		wantOutcome service.CallbackOutcome
		wantOneTime bool // expect non-empty one-time code
		wantErr     error
	}{
		{
			name: "identity match returns CallbackLogin with one-time code",
			setup: func(users *fakeUserStore, identities *fakeAuthIdentityStore) (*fakeOAuthProvider, *fakeUserStore, *fakeAuthIdentityStore) {
				u := seedOAuthUser(nil, users)
				seedAuthIdentity(nil, identities, u.ID, provider, "sub123")
				p := &fakeOAuthProvider{
					fetchIdentity: &oauth.Identity{ProviderSubject: "sub123", Email: u.Email, EmailVerified: true},
				}
				return p, users, identities
			},
			wantOutcome: service.CallbackLogin,
			wantOneTime: true,
		},
		{
			name: "new user (no collision) creates user and returns CallbackNewUser",
			setup: func(users *fakeUserStore, identities *fakeAuthIdentityStore) (*fakeOAuthProvider, *fakeUserStore, *fakeAuthIdentityStore) {
				p := &fakeOAuthProvider{
					fetchIdentity: &oauth.Identity{ProviderSubject: "newsub999", Email: "new@example.com", EmailVerified: true},
				}
				return p, users, identities
			},
			wantOutcome: service.CallbackNewUser,
			wantOneTime: true,
		},
		{
			name: "email collision returns CallbackEmailCollision (Design A: no auto-link)",
			setup: func(users *fakeUserStore, identities *fakeAuthIdentityStore) (*fakeOAuthProvider, *fakeUserStore, *fakeAuthIdentityStore) {
				// Seed an existing email-only user (no identity row for provider)
				now := time.Now().UTC()
				existing := &domain.User{
					ID:           uuid.New(),
					Email:        "collision@example.com",
					PasswordHash: func() *string { s := "hash"; return &s }(),
					DisplayName:  "Existing",
					AccountType:  domain.AccountTypePersonal,
					Status:       domain.UserStatusActive,
					CreatedAt:    now, UpdatedAt: now,
				}
				users.byID[existing.ID] = existing
				users.byEmail[existing.Email] = existing

				p := &fakeOAuthProvider{
					fetchIdentity: &oauth.Identity{
						ProviderSubject: "googleNewSub",
						Email:           "collision@example.com",
						EmailVerified:   true,
					},
				}
				return p, users, identities
			},
			wantOutcome: service.CallbackEmailCollision,
			wantOneTime: false,
		},
		{
			name: "suspended user returns ErrAccountSuspended",
			setup: func(users *fakeUserStore, identities *fakeAuthIdentityStore) (*fakeOAuthProvider, *fakeUserStore, *fakeAuthIdentityStore) {
				now := time.Now().UTC()
				u := &domain.User{
					ID:          uuid.New(),
					Email:       "suspended@example.com",
					DisplayName: "Suspended",
					AccountType: domain.AccountTypePersonal,
					Status:      domain.UserStatusSuspended,
					CreatedAt:   now, UpdatedAt: now,
				}
				users.byID[u.ID] = u
				users.byEmail[u.Email] = u
				seedAuthIdentity(nil, identities, u.ID, provider, "suspendedSub")
				p := &fakeOAuthProvider{
					fetchIdentity: &oauth.Identity{ProviderSubject: "suspendedSub", Email: u.Email},
				}
				return p, users, identities
			},
			wantErr: domain.ErrAccountSuspended,
		},
		{
			name: "invalid signed state returns ErrOAuthStateInvalid",
			setup: func(users *fakeUserStore, identities *fakeAuthIdentityStore) (*fakeOAuthProvider, *fakeUserStore, *fakeAuthIdentityStore) {
				return &fakeOAuthProvider{}, users, identities
			},
			wantErr: domain.ErrOAuthStateInvalid,
		},
		{
			name: "exchange code failure returns ErrOAuthExchangeFailed",
			setup: func(users *fakeUserStore, identities *fakeAuthIdentityStore) (*fakeOAuthProvider, *fakeUserStore, *fakeAuthIdentityStore) {
				p := &fakeOAuthProvider{exchangeErr: errors.New("provider error")}
				return p, users, identities
			},
			wantErr: domain.ErrOAuthExchangeFailed,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Each sub-test needs a fresh Redis (flush between cases)
			rdb := startOAuthTestRedis(t)

			users := newFakeUserStore()
			identities := newFakeAuthIdentityStore()

			p, users, identities := tc.setup(users, identities)

			svc := newOAuthSvc(t, users, identities, newFakeRefreshTokenStore(),
				map[string]service.OAuthProvider{provider: p}, rdb)

			// For invalid state test, skip issuing a real state and pass garbage.
			var signedState string
			if tc.name == "invalid signed state returns ErrOAuthStateInvalid" {
				signedState = "totally.invalid"
			} else {
				signedState = issueSignedState(t, svc)
			}

			res, err := svc.HandleCallback(context.Background(), provider, "authcode123", signedState)

			if tc.wantErr != nil {
				require.Error(t, err)
				assert.ErrorIs(t, err, tc.wantErr)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tc.wantOutcome, res.Outcome)

			if tc.wantOneTime {
				assert.NotEmpty(t, res.OneTimeCode)
			} else {
				assert.Empty(t, res.OneTimeCode)
			}
		})
	}
}

// --- TestOAuthService_HandleCallback_UnknownProvider ---

func TestOAuthService_HandleCallback_UnknownProvider(t *testing.T) {
	rdb := startOAuthTestRedis(t)

	svc := newOAuthSvc(
		t,
		newFakeUserStore(),
		newFakeAuthIdentityStore(),
		newFakeRefreshTokenStore(),
		map[string]service.OAuthProvider{
			"google": &fakeOAuthProvider{},
		},
		rdb,
	)

	_, err := svc.HandleCallback(context.Background(), "facebook", "code", "state.sig")
	require.Error(t, err)
	assert.ErrorIs(t, err, domain.ErrOAuthProviderUnknown)
}

// --- TestOAuthService_HandleCallback_StateSingleUse ---

func TestOAuthService_HandleCallback_StateSingleUse(t *testing.T) {
	rdb := startOAuthTestRedis(t)
	const provider = "google"

	svc := newOAuthSvc(
		t,
		newFakeUserStore(),
		newFakeAuthIdentityStore(),
		newFakeRefreshTokenStore(),
		map[string]service.OAuthProvider{
			provider: &fakeOAuthProvider{
				fetchIdentity: &oauth.Identity{ProviderSubject: "sub-replay", Email: "replay@example.com"},
			},
		},
		rdb,
	)

	signedState := issueSignedState(t, svc)

	// First use succeeds.
	_, err := svc.HandleCallback(context.Background(), provider, "code1", signedState)
	require.NoError(t, err)

	// Replay must fail — state was consumed (GetDel).
	_, err = svc.HandleCallback(context.Background(), provider, "code2", signedState)
	require.Error(t, err)
	assert.ErrorIs(t, err, domain.ErrOAuthStateInvalid)
}

// --- TestOAuthService_HandleCallback_Bind ---

func TestOAuthService_HandleCallback_Bind(t *testing.T) {
	const provider = "google"

	tests := []struct {
		name        string
		setup       func(users *fakeUserStore, identities *fakeAuthIdentityStore, bindUID uuid.UUID) *fakeOAuthProvider
		wantOutcome service.CallbackOutcome
		wantErr     error
	}{
		{
			name: "bind success",
			setup: func(_ *fakeUserStore, _ *fakeAuthIdentityStore, _ uuid.UUID) *fakeOAuthProvider {
				return &fakeOAuthProvider{
					fetchIdentity: &oauth.Identity{ProviderSubject: "newBindSub", Email: "bind@example.com"},
				}
			},
			wantOutcome: service.CallbackBindSuccess,
		},
		{
			name: "bind already bound identity returns ErrIdentityAlreadyBound",
			setup: func(_ *fakeUserStore, identities *fakeAuthIdentityStore, bindUID uuid.UUID) *fakeOAuthProvider {
				// Pre-seed the identity so Create returns ErrIdentityAlreadyBound.
				seedAuthIdentity(nil, identities, bindUID, provider, "alreadySub")
				return &fakeOAuthProvider{
					fetchIdentity: &oauth.Identity{ProviderSubject: "alreadySub"},
				}
			},
			wantErr: domain.ErrIdentityAlreadyBound,
		},
		{
			name: "exchange failure in bind returns ErrOAuthExchangeFailed",
			setup: func(_ *fakeUserStore, _ *fakeAuthIdentityStore, _ uuid.UUID) *fakeOAuthProvider {
				return &fakeOAuthProvider{exchangeErr: errors.New("network timeout")}
			},
			wantErr: domain.ErrOAuthExchangeFailed,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rdb := startOAuthTestRedis(t)
			users := newFakeUserStore()
			identities := newFakeAuthIdentityStore()

			// Create the user whose bind flow we'll use.
			bindUID := uuid.New()
			now := time.Now().UTC()
			u := &domain.User{
				ID:          bindUID,
				Email:       "bindme@example.com",
				AccountType: domain.AccountTypePersonal,
				Status:      domain.UserStatusActive,
				CreatedAt:   now, UpdatedAt: now,
			}
			users.byID[u.ID] = u
			users.byEmail[u.Email] = u

			p := tc.setup(users, identities, bindUID)

			svc := newOAuthSvc(t, users, identities, newFakeRefreshTokenStore(),
				map[string]service.OAuthProvider{provider: p}, rdb)

			// Issue a bind state for this user.
			ctx := context.Background()
			bindRes, err := svc.BindStart(ctx, provider, bindUID)
			require.NoError(t, err)

			// Extract signed state from the URL.
			const stateParam = "state="
			u2 := bindRes.AuthorizeURL
			idx := -1
			for i := 0; i+len(stateParam) <= len(u2); i++ {
				if u2[i:i+len(stateParam)] == stateParam {
					idx = i + len(stateParam)
					break
				}
			}
			require.True(t, idx > 0)
			signedState := u2[idx:]
			for i, ch := range signedState {
				if ch == '&' {
					signedState = signedState[:i]
					break
				}
			}

			res, err := svc.HandleCallback(ctx, provider, "bindcode", signedState)

			if tc.wantErr != nil {
				require.Error(t, err)
				assert.ErrorIs(t, err, tc.wantErr)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tc.wantOutcome, res.Outcome)
		})
	}
}

// --- TestOAuthService_Exchange ---

func TestOAuthService_Exchange(t *testing.T) {
	tests := []struct {
		name    string
		setup   func(users *fakeUserStore, svc *service.OAuthService, rdb *redis.Client) string // returns code
		wantErr error
	}{
		{
			name: "valid one-time code returns token pair",
			setup: func(users *fakeUserStore, svc *service.OAuthService, _ *redis.Client) string {
				// Issue a code by completing a callback cycle.
				identities := newFakeAuthIdentityStore()
				u := seedOAuthUser(nil, users)
				seedAuthIdentity(nil, identities, u.ID, "google", "exchangeSub")
				return "" // handled below differently
			},
		},
		{
			name:    "empty code returns ErrOAuthOneTimeCodeInvalid",
			setup:   func(_ *fakeUserStore, _ *service.OAuthService, _ *redis.Client) string { return "" },
			wantErr: domain.ErrOAuthOneTimeCodeInvalid,
		},
		{
			name:    "unknown code returns ErrOAuthOneTimeCodeInvalid",
			setup:   func(_ *fakeUserStore, _ *service.OAuthService, _ *redis.Client) string { return "no-such-code" },
			wantErr: domain.ErrOAuthOneTimeCodeInvalid,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rdb := startOAuthTestRedis(t)
			users := newFakeUserStore()
			identities := newFakeAuthIdentityStore()

			svc := newOAuthSvc(
				t, users, identities, newFakeRefreshTokenStore(),
				map[string]service.OAuthProvider{
					"google": &fakeOAuthProvider{
						fetchIdentity: &oauth.Identity{ProviderSubject: "exchangeSub", Email: "exch@example.com"},
					},
				},
				rdb,
			)

			var code string

			if tc.name == "valid one-time code returns token pair" {
				// Seed a known user+identity and run a full callback to get a real one-time code.
				u := seedOAuthUser(nil, users)
				seedAuthIdentity(nil, identities, u.ID, "google", "exchangeSub")

				signedState := issueSignedState(t, svc)
				cbRes, cbErr := svc.HandleCallback(context.Background(), "google", "code", signedState)
				require.NoError(t, cbErr)
				require.Equal(t, service.CallbackLogin, cbRes.Outcome)
				code = cbRes.OneTimeCode
			} else {
				code = tc.setup(users, svc, rdb)
			}

			res, err := svc.Exchange(context.Background(), code)

			if tc.wantErr != nil {
				require.Error(t, err)
				assert.ErrorIs(t, err, tc.wantErr)
				return
			}

			require.NoError(t, err)
			assert.NotEmpty(t, res.AccessToken)
			assert.NotEmpty(t, res.RefreshToken)
			assert.Greater(t, res.ExpiresIn, 0)
		})
	}
}

// --- TestOAuthService_Exchange_OneTimeCodeSingleUse ---

func TestOAuthService_Exchange_OneTimeCodeSingleUse(t *testing.T) {
	rdb := startOAuthTestRedis(t)
	users := newFakeUserStore()
	identities := newFakeAuthIdentityStore()

	u := seedOAuthUser(nil, users)
	seedAuthIdentity(nil, identities, u.ID, "google", "singleUseSub")

	svc := newOAuthSvc(
		t, users, identities, newFakeRefreshTokenStore(),
		map[string]service.OAuthProvider{
			"google": &fakeOAuthProvider{
				fetchIdentity: &oauth.Identity{ProviderSubject: "singleUseSub", Email: u.Email},
			},
		},
		rdb,
	)

	signedState := issueSignedState(t, svc)
	cbRes, err := svc.HandleCallback(context.Background(), "google", "code", signedState)
	require.NoError(t, err)
	code := cbRes.OneTimeCode

	// First exchange succeeds.
	_, err = svc.Exchange(context.Background(), code)
	require.NoError(t, err)

	// Replay must fail.
	_, err = svc.Exchange(context.Background(), code)
	require.Error(t, err)
	assert.ErrorIs(t, err, domain.ErrOAuthOneTimeCodeInvalid)
}

// --- TestOAuthService_Unbind ---

func TestOAuthService_Unbind(t *testing.T) {
	const provider = "google"

	tests := []struct {
		name    string
		setup   func(users *fakeUserStore, identities *fakeAuthIdentityStore) uuid.UUID
		wantErr error
	}{
		{
			name: "unbind succeeds when user has a password",
			setup: func(users *fakeUserStore, identities *fakeAuthIdentityStore) uuid.UUID {
				now := time.Now().UTC()
				hash := "argon2hash"
				u := &domain.User{
					ID:           uuid.New(),
					Email:        "withpw@example.com",
					PasswordHash: &hash,
					AccountType:  domain.AccountTypePersonal,
					Status:       domain.UserStatusActive,
					CreatedAt:    now, UpdatedAt: now,
				}
				users.byID[u.ID] = u
				users.byEmail[u.Email] = u
				seedAuthIdentity(nil, identities, u.ID, provider, "sub_withpw")
				return u.ID
			},
		},
		{
			name: "unbind succeeds when user has another identity",
			setup: func(users *fakeUserStore, identities *fakeAuthIdentityStore) uuid.UUID {
				u := seedOAuthUser(nil, users)
				seedAuthIdentity(nil, identities, u.ID, provider, "google_sub")
				seedAuthIdentity(nil, identities, u.ID, "line", "line_sub")
				return u.ID
			},
		},
		{
			name: "unbind last method returns ErrLastLoginMethod",
			setup: func(users *fakeUserStore, identities *fakeAuthIdentityStore) uuid.UUID {
				u := seedOAuthUser(nil, users) // no password
				seedAuthIdentity(nil, identities, u.ID, provider, "only_sub")
				return u.ID
			},
			wantErr: domain.ErrLastLoginMethod,
		},
		{
			name: "unknown provider returns ErrOAuthProviderUnknown",
			setup: func(users *fakeUserStore, identities *fakeAuthIdentityStore) uuid.UUID {
				u := seedOAuthUser(nil, users)
				return u.ID
			},
			wantErr: domain.ErrOAuthProviderUnknown,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rdb := startOAuthTestRedis(t)
			users := newFakeUserStore()
			identities := newFakeAuthIdentityStore()

			targetProvider := provider
			if tc.name == "unknown provider returns ErrOAuthProviderUnknown" {
				targetProvider = "facebook"
			}

			uid := tc.setup(users, identities)

			svc := newOAuthSvc(
				t, users, identities, newFakeRefreshTokenStore(),
				map[string]service.OAuthProvider{provider: &fakeOAuthProvider{}},
				rdb,
			)

			err := svc.Unbind(context.Background(), uid, targetProvider)

			if tc.wantErr != nil {
				require.Error(t, err)
				assert.ErrorIs(t, err, tc.wantErr)
				return
			}

			require.NoError(t, err)
		})
	}
}

// --- TestOAuthService_BindStart ---

func TestOAuthService_BindStart(t *testing.T) {
	tests := []struct {
		name     string
		provider string
		wantErr  error
	}{
		{
			name:     "returns authorize URL for known provider",
			provider: "google",
		},
		{
			name:     "unknown provider returns ErrOAuthProviderUnknown",
			provider: "twitter",
			wantErr:  domain.ErrOAuthProviderUnknown,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rdb := startOAuthTestRedis(t)

			svc := newOAuthSvc(
				t,
				newFakeUserStore(),
				newFakeAuthIdentityStore(),
				newFakeRefreshTokenStore(),
				map[string]service.OAuthProvider{"google": &fakeOAuthProvider{}},
				rdb,
			)

			res, err := svc.BindStart(context.Background(), tc.provider, uuid.New())

			if tc.wantErr != nil {
				require.Error(t, err)
				assert.ErrorIs(t, err, tc.wantErr)
				return
			}

			require.NoError(t, err)
			assert.NotEmpty(t, res.AuthorizeURL)
		})
	}
}

// --- TestOAuthService_NewUser_StatusPendingVerification ---

// TestOAuthService_NewUser_StatusPendingVerification asserts that when a new OAuth user
// is created via the callback flow their status is PENDING_VERIFICATION (not Active).
func TestOAuthService_NewUser_StatusPendingVerification(t *testing.T) {
	rdb := startOAuthTestRedis(t)
	const provider = "google"

	users := newFakeUserStore()
	identities := newFakeAuthIdentityStore()

	svc := newOAuthSvc(t, users, identities, newFakeRefreshTokenStore(),
		map[string]service.OAuthProvider{
			provider: &fakeOAuthProvider{
				fetchIdentity: &oauth.Identity{
					ProviderSubject: "statusCheckSub",
					Email:           "statuscheck@example.com",
					EmailVerified:   true,
				},
			},
		},
		rdb,
	)

	signedState := issueSignedState(t, svc)
	res, err := svc.HandleCallback(context.Background(), provider, "code", signedState)
	require.NoError(t, err)
	require.Equal(t, service.CallbackNewUser, res.Outcome)

	// Verify the created user has PENDING_VERIFICATION status.
	created := users.byEmail["statuscheck@example.com"]
	require.NotNil(t, created, "created user must exist in store")
	assert.Equal(t, domain.UserStatusPendingVerification, created.Status)
}

// --- TestOAuthService_LINENoEmail_TwoUsersDistinct ---

// TestOAuthService_LINENoEmail_TwoUsersDistinct proves that two LINE users without
// email permission each create a distinct user record — no unique-email crash.
func TestOAuthService_LINENoEmail_TwoUsersDistinct(t *testing.T) {
	const provider = "line"

	users := newFakeUserStore()
	identities := newFakeAuthIdentityStore()

	makeSvc := func(sub string) (*service.OAuthService, string) {
		rdb := startOAuthTestRedis(t)
		svc := newOAuthSvc(t, users, identities, newFakeRefreshTokenStore(),
			map[string]service.OAuthProvider{
				provider: &fakeOAuthProvider{
					fetchIdentity: &oauth.Identity{
						ProviderSubject: sub,
						Email:           "", // LINE user without email permission
						EmailVerified:   false,
					},
				},
			},
			rdb,
		)

		signedState := issueSignedStateForProvider(t, svc, provider)

		return svc, signedState
	}

	// First LINE user (no email).
	svc1, state1 := makeSvc("line_sub_aaa")
	res1, err := svc1.HandleCallback(context.Background(), provider, "code1", state1)
	require.NoError(t, err, "first LINE no-email user must create successfully")
	assert.Equal(t, service.CallbackNewUser, res1.Outcome)

	// Second LINE user (no email, different subject) — must NOT crash with email collision.
	svc2, state2 := makeSvc("line_sub_bbb")
	res2, err := svc2.HandleCallback(context.Background(), provider, "code2", state2)
	require.NoError(t, err, "second LINE no-email user must create successfully (no unique email crash)")
	assert.Equal(t, service.CallbackNewUser, res2.Outcome)

	// Both one-time codes must be distinct (separate users).
	assert.NotEqual(t, res1.OneTimeCode, res2.OneTimeCode)

	// Two distinct synthetic emails must be in the store.
	email1 := "oauth+line_sub_aaa@noemail.line.invalid"
	email2 := "oauth+line_sub_bbb@noemail.line.invalid"
	assert.NotNil(t, users.byEmail[email1], "first synthetic email must be stored")
	assert.NotNil(t, users.byEmail[email2], "second synthetic email must be stored")

	// Both users must have PENDING_VERIFICATION status and no password.
	u1 := users.byEmail[email1]
	u2 := users.byEmail[email2]
	assert.Equal(t, domain.UserStatusPendingVerification, u1.Status)
	assert.Equal(t, domain.UserStatusPendingVerification, u2.Status)
	assert.Nil(t, u1.PasswordHash)
	assert.Nil(t, u2.PasswordHash)
	assert.False(t, u1.EmailVerified)
	assert.False(t, u2.EmailVerified)
}

// --- TestOAuthService_ListIdentities ---

func TestOAuthService_ListIdentities(t *testing.T) {
	rdb := startOAuthTestRedis(t)

	tests := []struct {
		name            string
		setup           func(users *fakeUserStore, identities *fakeAuthIdentityStore) uuid.UUID
		wantCount       int
		wantHasPassword bool
		wantErr         error
	}{
		{
			name: "user with two identities and no password",
			setup: func(users *fakeUserStore, identities *fakeAuthIdentityStore) uuid.UUID {
				u := seedOAuthUser(nil, users) // no password
				seedAuthIdentity(nil, identities, u.ID, "google", "g_sub")
				seedAuthIdentity(nil, identities, u.ID, "line", "l_sub")
				return u.ID
			},
			wantCount:       2,
			wantHasPassword: false,
		},
		{
			name: "user with one identity and a password",
			setup: func(users *fakeUserStore, identities *fakeAuthIdentityStore) uuid.UUID {
				now := time.Now().UTC()
				hash := "argon2hash"
				u := &domain.User{
					ID:           uuid.New(),
					Email:        "withpw2@example.com",
					PasswordHash: &hash,
					AccountType:  domain.AccountTypePersonal,
					Status:       domain.UserStatusActive,
					CreatedAt:    now, UpdatedAt: now,
				}
				users.byID[u.ID] = u
				users.byEmail[u.Email] = u
				seedAuthIdentity(nil, identities, u.ID, "google", "g2_sub")
				return u.ID
			},
			wantCount:       1,
			wantHasPassword: true,
		},
		{
			name: "user with no identities",
			setup: func(users *fakeUserStore, identities *fakeAuthIdentityStore) uuid.UUID {
				u := seedOAuthUser(nil, users)
				return u.ID
			},
			wantCount:       0,
			wantHasPassword: false,
		},
		{
			name: "unknown user returns error",
			setup: func(_ *fakeUserStore, _ *fakeAuthIdentityStore) uuid.UUID {
				return uuid.New() // not in store
			},
			wantErr: domain.ErrNotFound,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			users := newFakeUserStore()
			identities := newFakeAuthIdentityStore()

			uid := tc.setup(users, identities)

			svc := newOAuthSvc(t, users, identities, newFakeRefreshTokenStore(),
				map[string]service.OAuthProvider{"google": &fakeOAuthProvider{}},
				rdb,
			)

			res, err := svc.ListIdentities(context.Background(), uid)

			if tc.wantErr != nil {
				require.Error(t, err)
				assert.ErrorIs(t, err, tc.wantErr)
				return
			}

			require.NoError(t, err)
			assert.Len(t, res.Identities, tc.wantCount)
			assert.Equal(t, tc.wantHasPassword, res.HasPassword)
		})
	}
}
