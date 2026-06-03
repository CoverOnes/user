package service_test

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/CoverOnes/user/internal/auth/jwt"
	"github.com/CoverOnes/user/internal/auth/password"
	"github.com/CoverOnes/user/internal/auth/refresh"
	"github.com/CoverOnes/user/internal/domain"
	"github.com/CoverOnes/user/internal/service"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const validPassword = "superSecurePassword123" // ≥12 chars, meets complexity

// newAuthService builds an AuthService over the supplied fakes with an ephemeral
// signer. tx is nil so Register uses the sequential fallback path.
func newAuthService(
	t *testing.T,
	users *fakeUserStore,
	companies *fakeCompanyStore,
	rts *fakeRefreshTokenStore,
) *service.AuthService {
	t.Helper()

	signer, err := jwt.NewEphemeralSigner(10 * time.Minute)
	require.NoError(t, err)

	return service.NewAuthService(users, companies, rts, nil, signer, 10*time.Minute, 24)
}

// seedUser inserts an active user with the given email/password into the fake store
// and returns it.
func seedUser(t *testing.T, users *fakeUserStore, email string) *domain.User {
	t.Helper()

	hash, err := password.Hash(validPassword, password.DefaultParams)
	require.NoError(t, err)

	now := time.Now().UTC()
	u := &domain.User{
		ID:           uuid.New(),
		Email:        email,
		PasswordHash: hash,
		DisplayName:  "Seed",
		AccountType:  domain.AccountTypePersonal,
		Status:       domain.UserStatusActive,
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	users.put(u)

	return u
}

func TestAuthService_Register(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		in        service.RegisterInput
		setup     func(u *fakeUserStore, c *fakeCompanyStore)
		wantErr   error
		assertOut func(t *testing.T, out *service.RegisterOutput, c *fakeCompanyStore)
	}{
		{
			name: "happy path personal",
			in: service.RegisterInput{
				Email:       "Alice@Example.com",
				Password:    validPassword,
				DisplayName: "Alice",
				AccountType: domain.AccountTypePersonal,
			},
			assertOut: func(t *testing.T, out *service.RegisterOutput, c *fakeCompanyStore) {
				require.NotNil(t, out)
				// Email is lowercased + trimmed.
				assert.Equal(t, "alice@example.com", out.User.Email)
				assert.Empty(t, c.created, "personal account must not create a company")
			},
		},
		{
			name: "happy path company creates company row",
			in: service.RegisterInput{
				Email:       "owner@corp.com",
				Password:    validPassword,
				DisplayName: "Owner",
				AccountType: domain.AccountTypeCompany,
				CompanyName: "Acme Inc",
			},
			assertOut: func(t *testing.T, out *service.RegisterOutput, c *fakeCompanyStore) {
				require.NotNil(t, out)
				require.Len(t, c.created, 1)
				assert.Equal(t, "Acme Inc", c.created[0].Name)
				assert.Equal(t, out.User.ID, c.created[0].OwnerUserID)
			},
		},
		{
			name: "invalid account type rejected as invalid credentials (no enumeration)",
			in: service.RegisterInput{
				Email:       "x@example.com",
				Password:    validPassword,
				DisplayName: "X",
				AccountType: "ROBOT",
			},
			wantErr: domain.ErrInvalidCredentials,
		},
		{
			name: "company account without company name",
			in: service.RegisterInput{
				Email:       "noname@corp.com",
				Password:    validPassword,
				DisplayName: "NoName",
				AccountType: domain.AccountTypeCompany,
				CompanyName: "   ",
			},
			wantErr: domain.ErrCompanyNameRequired,
		},
		{
			name: "weak password rejected",
			in: service.RegisterInput{
				Email:       "weak@example.com",
				Password:    "short",
				DisplayName: "Weak",
				AccountType: domain.AccountTypePersonal,
			},
			wantErr: domain.ErrWeakPassword,
		},
		{
			name: "duplicate email surfaces store error",
			in: service.RegisterInput{
				Email:       "dup@example.com",
				Password:    validPassword,
				DisplayName: "Dup",
				AccountType: domain.AccountTypePersonal,
			},
			setup: func(u *fakeUserStore, _ *fakeCompanyStore) {
				seedUser(t, u, "dup@example.com")
			},
			wantErr: domain.ErrEmailTaken,
		},
		{
			name: "company-store failure surfaces (atomicity intent)",
			in: service.RegisterInput{
				Email:       "co-fail@corp.com",
				Password:    validPassword,
				DisplayName: "CoFail",
				AccountType: domain.AccountTypeCompany,
				CompanyName: "Acme",
			},
			setup: func(_ *fakeUserStore, c *fakeCompanyStore) {
				c.createErr = errInjected
			},
			wantErr: errInjected,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			users := newFakeUserStore()
			companies := &fakeCompanyStore{}
			rts := newFakeRefreshTokenStore()
			if tc.setup != nil {
				tc.setup(users, companies)
			}

			svc := newAuthService(t, users, companies, rts)
			out, err := svc.Register(context.Background(), tc.in)

			if tc.wantErr != nil {
				require.Error(t, err)
				assert.ErrorIs(t, err, tc.wantErr)
				assert.Nil(t, out)

				return
			}

			require.NoError(t, err)
			if tc.assertOut != nil {
				tc.assertOut(t, out, companies)
			}
		})
	}
}

func TestAuthService_Login(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		email   string
		pass    string
		setup   func(u *fakeUserStore)
		wantErr error
		wantOK  bool
	}{
		{
			name:   "happy path issues token pair",
			email:  "good@example.com",
			pass:   validPassword,
			setup:  func(u *fakeUserStore) { seedUser(t, u, "good@example.com") },
			wantOK: true,
		},
		{
			name:    "unknown email maps to invalid credentials (no enumeration)",
			email:   "ghost@example.com",
			pass:    validPassword,
			wantErr: domain.ErrInvalidCredentials,
		},
		{
			name:    "wrong password",
			email:   "wrong@example.com",
			pass:    "totallyWrongPassword!",
			setup:   func(u *fakeUserStore) { seedUser(t, u, "wrong@example.com") },
			wantErr: domain.ErrInvalidCredentials,
		},
		{
			name:  "suspended account rejected",
			email: "suspended@example.com",
			pass:  validPassword,
			setup: func(u *fakeUserStore) {
				usr := seedUser(t, u, "suspended@example.com")
				usr.Status = domain.UserStatusSuspended
				u.put(usr)
			},
			wantErr: domain.ErrAccountSuspended,
		},
		{
			name:    "store error other than not-found is propagated",
			email:   "boom@example.com",
			pass:    validPassword,
			setup:   func(u *fakeUserStore) { u.getByEmailErr = errInjected },
			wantErr: errInjected,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			users := newFakeUserStore()
			rts := newFakeRefreshTokenStore()
			if tc.setup != nil {
				tc.setup(users)
			}

			svc := newAuthService(t, users, &fakeCompanyStore{}, rts)
			pair, err := svc.Login(context.Background(), service.LoginInput{
				Email:    tc.email,
				Password: tc.pass,
				IPAddr:   netip.MustParseAddr("203.0.113.1"),
			})

			if tc.wantErr != nil {
				require.Error(t, err)
				assert.ErrorIs(t, err, tc.wantErr)
				assert.Nil(t, pair)

				return
			}

			require.NoError(t, err)
			require.NotNil(t, pair)
			assert.NotEmpty(t, pair.AccessToken)
			assert.NotEmpty(t, pair.RefreshToken)
			assert.Len(t, rts.tokens, 1, "login must persist exactly one refresh token")
		})
	}
}

// loginAndGetToken runs a successful login and returns the raw refresh token plus
// the persisted record, for use in Refresh/Logout tests.
func loginAndGetToken(t *testing.T, svc *service.AuthService, rts *fakeRefreshTokenStore, email string) (string, *domain.RefreshToken) {
	t.Helper()

	pair, err := svc.Login(context.Background(), service.LoginInput{
		Email:    email,
		Password: validPassword,
		IPAddr:   netip.MustParseAddr("203.0.113.2"),
	})
	require.NoError(t, err)

	parsed, err := refresh.Parse(pair.RefreshToken)
	require.NoError(t, err)

	rt := rts.tokens[parsed.ID]
	require.NotNil(t, rt)

	return pair.RefreshToken, rt
}

func TestAuthService_Refresh_HappyPath(t *testing.T) {
	t.Parallel()

	users := newFakeUserStore()
	rts := newFakeRefreshTokenStore()
	seedUser(t, users, "refresh@example.com")
	svc := newAuthService(t, users, &fakeCompanyStore{}, rts)

	raw, oldRT := loginAndGetToken(t, svc, rts, "refresh@example.com")

	pair, err := svc.Refresh(context.Background(), service.RefreshInput{
		RawToken: raw,
		IPAddr:   netip.MustParseAddr("203.0.113.3"),
	})
	require.NoError(t, err)
	require.NotNil(t, pair)
	assert.NotEqual(t, raw, pair.RefreshToken, "rotation must yield a new token")

	// Old token marked used.
	assert.NotNil(t, rts.tokens[oldRT.ID].UsedAt)

	// New token chains to old via prev_id and stays in the same family.
	parsedNew, err := refresh.Parse(pair.RefreshToken)
	require.NoError(t, err)
	newRT := rts.tokens[parsedNew.ID]
	require.NotNil(t, newRT.PrevID)
	assert.Equal(t, oldRT.ID, *newRT.PrevID)
	assert.Equal(t, oldRT.FamilyID, newRT.FamilyID)
}

func TestAuthService_Refresh_ErrorPaths(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		mutate  func(t *testing.T, svc *service.AuthService, rts *fakeRefreshTokenStore, users *fakeUserStore, raw string, rt *domain.RefreshToken) string
		wantErr error
		// wantFamilyRevoked asserts the whole family was revoked (reuse / version mismatch).
		wantFamilyRevoked bool
	}{
		{
			name: "malformed token",
			mutate: func(_ *testing.T, _ *service.AuthService, _ *fakeRefreshTokenStore, _ *fakeUserStore, _ string, _ *domain.RefreshToken) string {
				return "not-a-token"
			},
			wantErr: domain.ErrInvalidRefresh,
		},
		{
			name: "unknown token id",
			mutate: func(t *testing.T, _ *service.AuthService, _ *fakeRefreshTokenStore, _ *fakeUserStore, _ string, _ *domain.RefreshToken) string {
				tok, err := refresh.Generate()
				require.NoError(t, err)

				return tok.Raw
			},
			wantErr: domain.ErrInvalidRefresh,
		},
		{
			name: "reuse of a consumed token revokes family",
			mutate: func(t *testing.T, svc *service.AuthService, _ *fakeRefreshTokenStore, _ *fakeUserStore, raw string, _ *domain.RefreshToken) string {
				// Consume once so used_at is set.
				_, err := svc.Refresh(context.Background(), service.RefreshInput{RawToken: raw})
				require.NoError(t, err)

				return raw // present the consumed token again
			},
			wantErr:           domain.ErrRefreshReuse,
			wantFamilyRevoked: true,
		},
		{
			name: "expired token",
			mutate: func(_ *testing.T, _ *service.AuthService, rts *fakeRefreshTokenStore, _ *fakeUserStore, raw string, rt *domain.RefreshToken) string {
				rts.tokens[rt.ID].ExpiresAt = time.Now().UTC().Add(-time.Hour)

				return raw
			},
			wantErr: domain.ErrRefreshExpired,
		},
		{
			name: "token_version mismatch revokes family",
			mutate: func(_ *testing.T, _ *service.AuthService, rts *fakeRefreshTokenStore, users *fakeUserStore, raw string, rt *domain.RefreshToken) string {
				// Bump the user's version so the stored token's snapshot is stale.
				u := users.byID[rt.UserID]
				u.TokenVersion = rt.TokenVersion + 1

				return raw
			},
			wantErr:           domain.ErrInvalidRefresh,
			wantFamilyRevoked: true,
		},
		{
			name: "mark-used store error propagates",
			mutate: func(_ *testing.T, _ *service.AuthService, rts *fakeRefreshTokenStore, _ *fakeUserStore, raw string, _ *domain.RefreshToken) string {
				rts.markUsedErr = errInjected

				return raw
			},
			wantErr: errInjected,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			users := newFakeUserStore()
			rts := newFakeRefreshTokenStore()
			seedUser(t, users, "err@example.com")
			svc := newAuthService(t, users, &fakeCompanyStore{}, rts)

			raw, rt := loginAndGetToken(t, svc, rts, "err@example.com")
			present := tc.mutate(t, svc, rts, users, raw, rt)

			_, err := svc.Refresh(context.Background(), service.RefreshInput{RawToken: present})
			require.Error(t, err)
			assert.ErrorIs(t, err, tc.wantErr)

			if tc.wantFamilyRevoked {
				assert.True(t, rts.familyRevoked(rt.FamilyID), "family should be revoked")
			}
		})
	}
}

func TestAuthService_Logout(t *testing.T) {
	t.Parallel()

	t.Run("happy path revokes family", func(t *testing.T) {
		t.Parallel()

		users := newFakeUserStore()
		rts := newFakeRefreshTokenStore()
		seedUser(t, users, "logout@example.com")
		svc := newAuthService(t, users, &fakeCompanyStore{}, rts)

		raw, rt := loginAndGetToken(t, svc, rts, "logout@example.com")

		require.NoError(t, svc.Logout(context.Background(), raw))
		assert.True(t, rts.familyRevoked(rt.FamilyID))
	})

	t.Run("malformed token rejected", func(t *testing.T) {
		t.Parallel()

		svc := newAuthService(t, newFakeUserStore(), &fakeCompanyStore{}, newFakeRefreshTokenStore())
		err := svc.Logout(context.Background(), "garbage")
		assert.ErrorIs(t, err, domain.ErrInvalidRefresh)
	})

	t.Run("wrong token hash for valid id is rejected (F1 binding)", func(t *testing.T) {
		t.Parallel()

		users := newFakeUserStore()
		rts := newFakeRefreshTokenStore()
		seedUser(t, users, "bind@example.com")
		svc := newAuthService(t, users, &fakeCompanyStore{}, rts)

		_, rt := loginAndGetToken(t, svc, rts, "bind@example.com")

		// Craft a raw token with the real ID but a different (attacker) secret.
		forged, err := refresh.Generate()
		require.NoError(t, err)
		spoof := rt.ID.String() + "." + forged.Secret

		err = svc.Logout(context.Background(), spoof)
		assert.ErrorIs(t, err, domain.ErrInvalidRefresh)
		assert.False(t, rts.familyRevoked(rt.FamilyID), "a spoofed hash must not revoke the victim family")
	})

	t.Run("unknown token id rejected", func(t *testing.T) {
		t.Parallel()

		svc := newAuthService(t, newFakeUserStore(), &fakeCompanyStore{}, newFakeRefreshTokenStore())
		tok, err := refresh.Generate()
		require.NoError(t, err)

		err = svc.Logout(context.Background(), tok.Raw)
		assert.ErrorIs(t, err, domain.ErrInvalidRefresh)
	})
}

func TestAuthService_LogoutAll(t *testing.T) {
	t.Parallel()

	t.Run("happy path bumps token version", func(t *testing.T) {
		t.Parallel()

		users := newFakeUserStore()
		u := seedUser(t, users, "all@example.com")
		svc := newAuthService(t, users, &fakeCompanyStore{}, newFakeRefreshTokenStore())

		require.NoError(t, svc.LogoutAll(context.Background(), u.ID))
		assert.Equal(t, 1, users.byID[u.ID].TokenVersion)
	})

	t.Run("store error propagates", func(t *testing.T) {
		t.Parallel()

		users := newFakeUserStore()
		users.bumpVersionErr = errInjected
		svc := newAuthService(t, users, &fakeCompanyStore{}, newFakeRefreshTokenStore())

		err := svc.LogoutAll(context.Background(), uuid.New())
		require.Error(t, err)
		assert.True(t, errors.Is(err, errInjected))
	})
}
