package service_test

import (
	"context"
	"crypto/sha256"
	"errors"
	"net/netip"
	"strings"
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

// validTWNationalID is a checksum-valid Taiwan national ID used in fixtures
// (canonical example, matching the kyc test suite). NOT a real person's ID.
const validTWNationalID = "A123456789"

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
				LegalName:   "Alice Wang",
				NationalID:  validTWNationalID,
			},
			assertOut: func(t *testing.T, out *service.RegisterOutput, c *fakeCompanyStore) {
				require.NotNil(t, out)
				// Email is lowercased + trimmed.
				assert.Equal(t, "alice@example.com", out.User.Email)
				assert.Empty(t, c.created, "personal account must not create a company")
				// New status + email_verified contract.
				assert.Equal(t, domain.UserStatusPendingVerification, out.User.Status)
				assert.False(t, out.User.EmailVerified)
			},
		},
		{
			name: "happy path company creates company row",
			in: service.RegisterInput{
				Email:       "owner@corp.com",
				Password:    validPassword,
				DisplayName: "Owner",
				AccountType: domain.AccountTypeCompany,
				LegalName:   "Owner Lin",
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
				LegalName:   "Weak Wang",
				NationalID:  validTWNationalID,
			},
			wantErr: domain.ErrWeakPassword,
		},
		{
			name: "legal name required for personal",
			in: service.RegisterInput{
				Email:       "noname@example.com",
				Password:    validPassword,
				DisplayName: "NoName",
				AccountType: domain.AccountTypePersonal,
				LegalName:   "",
				NationalID:  validTWNationalID,
			},
			wantErr: domain.ErrValidation,
		},
		{
			name: "legal name required for company",
			in: service.RegisterInput{
				Email:       "co-noname@corp.com",
				Password:    validPassword,
				DisplayName: "CoNoName",
				AccountType: domain.AccountTypeCompany,
				CompanyName: "Acme",
				LegalName:   "",
			},
			wantErr: domain.ErrValidation,
		},
		{
			name: "personal national id checksum invalid rejected",
			in: service.RegisterInput{
				Email:       "badid@example.com",
				Password:    validPassword,
				DisplayName: "BadID",
				AccountType: domain.AccountTypePersonal,
				LegalName:   "Bad ID",
				NationalID:  "A123456788", // valid structure, wrong check digit
			},
			wantErr: domain.ErrValidation,
		},
		{
			name: "company ignores national id (optional)",
			in: service.RegisterInput{
				Email:       "co-noid@corp.com",
				Password:    validPassword,
				DisplayName: "CoNoID",
				AccountType: domain.AccountTypeCompany,
				CompanyName: "NoID Corp",
				LegalName:   "Owner Chen",
				NationalID:  "", // ignored for COMPANY
			},
			assertOut: func(t *testing.T, out *service.RegisterOutput, c *fakeCompanyStore) {
				require.NotNil(t, out)
				require.Len(t, c.created, 1)
			},
		},
		{
			name: "company name over 200 runes rejected (P1 DoS guard)",
			in: service.RegisterInput{
				Email:       "toolong@corp.com",
				Password:    validPassword,
				DisplayName: "TooLong",
				AccountType: domain.AccountTypeCompany,
				LegalName:   "Too Long",
				CompanyName: strings.Repeat("x", 201),
			},
			wantErr: domain.ErrCompanyNameTooLong,
		},
		{
			name: "company name exactly 200 runes accepted (boundary)",
			in: service.RegisterInput{
				Email:       "boundary@corp.com",
				Password:    validPassword,
				DisplayName: "Boundary",
				AccountType: domain.AccountTypeCompany,
				LegalName:   "Boundary Co",
				CompanyName: strings.Repeat("x", 200),
			},
			assertOut: func(t *testing.T, out *service.RegisterOutput, c *fakeCompanyStore) {
				require.NotNil(t, out)
				require.Len(t, c.created, 1)
				assert.Equal(t, 200, len(c.created[0].Name))
			},
		},
		{
			name: "company name 200 multibyte runes accepted (rune not byte count)",
			in: service.RegisterInput{
				Email:       "multibyte@corp.com",
				Password:    validPassword,
				DisplayName: "Multibyte",
				AccountType: domain.AccountTypeCompany,
				LegalName:   "Multibyte Co",
				// 200 runes of a 3-byte character = 600 bytes but only 200 runes.
				CompanyName: strings.Repeat("公", 200),
			},
			assertOut: func(t *testing.T, out *service.RegisterOutput, c *fakeCompanyStore) {
				require.NotNil(t, out)
				require.Len(t, c.created, 1)
			},
		},
		{
			name: "duplicate email surfaces store error",
			in: service.RegisterInput{
				Email:       "dup@example.com",
				Password:    validPassword,
				DisplayName: "Dup",
				AccountType: domain.AccountTypePersonal,
				LegalName:   "Dup Wang",
				NationalID:  validTWNationalID,
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
				LegalName:   "Co Fail",
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

// TestAuthService_Register_VerificationEmailFailureStillPersists is the load-bearing
// proof of the headline guarantee: a verification-email SMTP failure on the
// post-commit send MUST NOT roll back the user. It wires a verification-capable
// service whose mailer ALWAYS errors (spyMailer.sendErr injected) and asserts that
// Register still returns NoError + a non-nil user AND that the user row is persisted
// in the store. The send is detached (FIX 2), so we drain it via WaitForPendingSends
// (no time.Sleep) and then confirm the failing mailer was in fact invoked — proving
// the error was exercised on the real send path, not silently skipped. If Register
// ever propagated the mailer error, require.NoError below would fail.
func TestAuthService_Register_VerificationEmailFailureStillPersists(t *testing.T) {
	t.Parallel()

	users := newFakeUserStore()
	verifications := newFakeVerificationStore()
	mailer := &spyMailer{sendErr: errInjected} // every SendVerification returns this error

	svc := newVerificationService(t, users, verifications, mailer, allowAllLimiter{})

	out, err := svc.Register(context.Background(), service.RegisterInput{
		Email:       "Persist@Example.com",
		Password:    validPassword,
		DisplayName: "Persist",
		AccountType: domain.AccountTypePersonal,
		LegalName:   "Persist Wang",
		NationalID:  validTWNationalID,
	})

	// The SMTP failure must NOT propagate — Register still succeeds with the user.
	require.NoError(t, err, "SMTP failure on post-commit send must not fail Register")
	require.NotNil(t, out)
	require.NotNil(t, out.User)

	// The user row is persisted (committed before the email send) and queryable by
	// the normalized email, proving the account exists despite the email failure.
	persisted, getErr := users.GetByEmail(context.Background(), "persist@example.com")
	require.NoError(t, getErr, "user must be persisted in the store")
	require.NotNil(t, persisted)
	assert.Equal(t, out.User.ID, persisted.ID)
	assert.Equal(t, domain.UserStatusPendingVerification, persisted.Status)
	assert.False(t, persisted.EmailVerified)

	// A verification token row was committed alongside the user.
	assert.Len(t, verifications.byHash, 1, "a verification token must be persisted")

	// Drain the detached send (deterministic, no time.Sleep) and confirm the failing
	// mailer was actually invoked — the injected error was exercised on the real path.
	svc.WaitForPendingSends()
	assert.Equal(t, 1, mailer.sendCount(), "the (failing) verification email must be attempted exactly once")
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
			name:  "suspended account with correct password reveals suspension",
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
			// Enumeration mitigation (P1): a suspended account probed with the WRONG
			// password must return the SAME generic INVALID_CREDENTIALS as any other
			// failed login, so an attacker cannot discover which accounts are suspended.
			name:  "suspended account with wrong password hides suspension (no enumeration)",
			email: "suspended-wrong@example.com",
			pass:  "totallyWrongPassword!",
			setup: func(u *fakeUserStore) {
				usr := seedUser(t, u, "suspended-wrong@example.com")
				usr.Status = domain.UserStatusSuspended
				u.put(usr)
			},
			wantErr: domain.ErrInvalidCredentials,
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

// fakeLoginLimiter is a controllable LoginRateLimiter for unit tests. It records the
// emails it was asked about and returns the configured verdict.
type fakeLoginLimiter struct {
	allow bool
	seen  []string
}

func (f *fakeLoginLimiter) Allow(_ context.Context, normalizedEmail string) bool {
	f.seen = append(f.seen, normalizedEmail)

	return f.allow
}

func TestAuthService_Login_PerEmailRateLimit(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		allow       bool
		wantErr     error
		wantOK      bool
		wantChecked bool
	}{
		{
			name:        "limiter allows -> login succeeds",
			allow:       true,
			wantOK:      true,
			wantChecked: true,
		},
		{
			name:        "limiter denies -> rate limited before password check",
			allow:       false,
			wantErr:     domain.ErrLoginRateLimited,
			wantChecked: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			users := newFakeUserStore()
			rts := newFakeRefreshTokenStore()
			seedUser(t, users, "limited@example.com")

			limiter := &fakeLoginLimiter{allow: tc.allow}
			svc := newAuthService(t, users, &fakeCompanyStore{}, rts).WithLoginRateLimiter(limiter)

			pair, err := svc.Login(context.Background(), service.LoginInput{
				Email:    "Limited@Example.com", // mixed case to prove normalization
				Password: validPassword,
				IPAddr:   netip.MustParseAddr("203.0.113.9"),
			})

			if tc.wantChecked {
				require.Len(t, limiter.seen, 1)
				assert.Equal(t, "limited@example.com", limiter.seen[0], "limiter must be keyed by normalized email")
			}

			if tc.wantErr != nil {
				require.Error(t, err)
				assert.ErrorIs(t, err, tc.wantErr)
				assert.Nil(t, pair)

				return
			}

			require.NoError(t, err)
			require.NotNil(t, pair)
			assert.NotEmpty(t, pair.AccessToken)
		})
	}
}

func TestAuthService_Login_RateLimitDeniedSkipsDBAndPassword(t *testing.T) {
	t.Parallel()

	// No user is seeded and getByEmailErr is set: if the limiter denied correctly,
	// the service returns ErrLoginRateLimited WITHOUT touching the store, so the
	// injected store error is never surfaced.
	users := newFakeUserStore()
	users.getByEmailErr = errInjected
	rts := newFakeRefreshTokenStore()

	limiter := &fakeLoginLimiter{allow: false}
	svc := newAuthService(t, users, &fakeCompanyStore{}, rts).WithLoginRateLimiter(limiter)

	_, err := svc.Login(context.Background(), service.LoginInput{
		Email:    "spray@example.com",
		Password: "whatever",
		IPAddr:   netip.MustParseAddr("203.0.113.10"),
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, domain.ErrLoginRateLimited)
	assert.NotErrorIs(t, err, errInjected, "rate-limit denial must short-circuit before the store call")
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
		{
			// Fix 3: suspended user must not keep refreshing after account suspension.
			// Login already checks for suspension; Refresh now does too so a user
			// suspended after login cannot refresh tokens for the remaining ~24 h TTL.
			name: "suspended user is rejected and family is revoked",
			mutate: func(_ *testing.T, _ *service.AuthService, _ *fakeRefreshTokenStore, users *fakeUserStore, raw string, rt *domain.RefreshToken) string {
				// Suspend the user between login (issuance) and refresh.
				u := users.byID[rt.UserID]
				u.Status = domain.UserStatusSuspended

				return raw
			},
			wantErr:           domain.ErrAccountSuspended,
			wantFamilyRevoked: true,
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

// newVerificationService builds an AuthService wired with verification deps
// (token store + encryptor + mailer spy + optional resend limiter).
func newVerificationService(
	t *testing.T,
	users *fakeUserStore,
	verifications *fakeVerificationStore,
	mailer *spyMailer,
	resend service.EmailRateLimiter,
) *service.AuthService {
	t.Helper()

	signer, err := jwt.NewEphemeralSigner(10 * time.Minute)
	require.NoError(t, err)

	svc := service.NewAuthService(users, &fakeCompanyStore{}, newFakeRefreshTokenStore(), nil, signer, 10*time.Minute, 24)

	return svc.WithVerification(verifications, &noopEncryptor{}, mailer, resend)
}

// seedVerificationToken hashes rawToken (SHA-256) and stores a token row for the
// given user with the supplied expiry / consumed state.
func seedVerificationToken(
	t *testing.T,
	verifications *fakeVerificationStore,
	userID uuid.UUID,
	rawToken string,
	expiresAt time.Time,
	consumedAt *time.Time,
) {
	t.Helper()

	sum := sha256.Sum256([]byte(rawToken))
	vt := &domain.EmailVerificationToken{
		ID:         uuid.New(),
		UserID:     userID,
		TokenHash:  sum[:],
		ExpiresAt:  expiresAt,
		ConsumedAt: consumedAt,
		CreatedAt:  time.Now().UTC(),
	}
	require.NoError(t, verifications.Create(context.Background(), vt))
}

func TestAuthService_VerifyEmail(t *testing.T) {
	t.Parallel()

	t.Run("happy path sets email_verified and consumes token", func(t *testing.T) {
		t.Parallel()

		users := newFakeUserStore()
		u := seedUser(t, users, "verify@example.com")
		verifications := newFakeVerificationStore()
		seedVerificationToken(t, verifications, u.ID, "raw-token-1", time.Now().UTC().Add(time.Hour), nil)

		svc := newVerificationService(t, users, verifications, &spyMailer{}, nil)

		require.NoError(t, svc.VerifyEmail(context.Background(), "raw-token-1"))
		assert.True(t, users.byID[u.ID].EmailVerified, "user must be marked email_verified")
		assert.Equal(t, int16(1), users.byID[u.ID].KYCTier, "email verification must promote the account to Tier 1")
	})

	t.Run("happy path does not downgrade existing higher KYC tier", func(t *testing.T) {
		t.Parallel()

		users := newFakeUserStore()
		u := seedUser(t, users, "tier2@example.com")
		users.byID[u.ID].KYCTier = 2
		verifications := newFakeVerificationStore()
		seedVerificationToken(t, verifications, u.ID, "raw-token-tier2", time.Now().UTC().Add(time.Hour), nil)

		svc := newVerificationService(t, users, verifications, &spyMailer{}, nil)

		require.NoError(t, svc.VerifyEmail(context.Background(), "raw-token-tier2"))
		assert.True(t, users.byID[u.ID].EmailVerified, "user must be marked email_verified")
		assert.Equal(t, int16(2), users.byID[u.ID].KYCTier, "email verification must not downgrade existing KYC tier")
	})

	t.Run("single-use: second verify with same token fails", func(t *testing.T) {
		t.Parallel()

		users := newFakeUserStore()
		u := seedUser(t, users, "single@example.com")
		verifications := newFakeVerificationStore()
		seedVerificationToken(t, verifications, u.ID, "raw-token-2", time.Now().UTC().Add(time.Hour), nil)

		svc := newVerificationService(t, users, verifications, &spyMailer{}, nil)

		require.NoError(t, svc.VerifyEmail(context.Background(), "raw-token-2"))

		err := svc.VerifyEmail(context.Background(), "raw-token-2")
		require.ErrorIs(t, err, domain.ErrInvalidVerificationToken)
	})

	t.Run("expired token fails with generic error", func(t *testing.T) {
		t.Parallel()

		users := newFakeUserStore()
		u := seedUser(t, users, "expired@example.com")
		verifications := newFakeVerificationStore()
		seedVerificationToken(t, verifications, u.ID, "raw-token-3", time.Now().UTC().Add(-time.Hour), nil)

		svc := newVerificationService(t, users, verifications, &spyMailer{}, nil)

		err := svc.VerifyEmail(context.Background(), "raw-token-3")
		require.ErrorIs(t, err, domain.ErrInvalidVerificationToken)
		assert.False(t, users.byID[u.ID].EmailVerified, "expired token must not verify the user")
	})

	t.Run("already-consumed token fails with generic error", func(t *testing.T) {
		t.Parallel()

		users := newFakeUserStore()
		u := seedUser(t, users, "consumed@example.com")
		verifications := newFakeVerificationStore()
		consumed := time.Now().UTC().Add(-time.Minute)
		seedVerificationToken(t, verifications, u.ID, "raw-token-4", time.Now().UTC().Add(time.Hour), &consumed)

		svc := newVerificationService(t, users, verifications, &spyMailer{}, nil)

		err := svc.VerifyEmail(context.Background(), "raw-token-4")
		require.ErrorIs(t, err, domain.ErrInvalidVerificationToken)
	})

	t.Run("unknown token fails with same generic error (no oracle)", func(t *testing.T) {
		t.Parallel()

		users := newFakeUserStore()
		verifications := newFakeVerificationStore()
		svc := newVerificationService(t, users, verifications, &spyMailer{}, nil)

		err := svc.VerifyEmail(context.Background(), "never-issued")
		require.ErrorIs(t, err, domain.ErrInvalidVerificationToken)
	})

	t.Run("empty token rejected", func(t *testing.T) {
		t.Parallel()

		svc := newVerificationService(t, newFakeUserStore(), newFakeVerificationStore(), &spyMailer{}, nil)
		err := svc.VerifyEmail(context.Background(), "   ")
		require.ErrorIs(t, err, domain.ErrInvalidVerificationToken)
	})
}

// TestAuthService_VerifyEmail_TxRollback verifies the atomicity guarantee introduced
// in Fix 1: when SetEmailVerified fails AFTER MarkConsumed succeeds, both writes must
// be rolled back so the token is not consumed-but-email-unverified. The in-memory fake
// exercises the sequential fallback path; the WithTx path is covered by the Postgres
// integration test (verification_store_integration_test.go).
func TestAuthService_VerifyEmail_TxRollback(t *testing.T) {
	t.Parallel()

	t.Run("SetEmailVerified failure leaves token unconsumed (sequential fallback rollback intent)", func(t *testing.T) {
		t.Parallel()

		users := newFakeUserStore()
		u := seedUser(t, users, "rollback@example.com")
		verifications := newFakeVerificationStore()
		seedVerificationToken(t, verifications, u.ID, "rb-token", time.Now().UTC().Add(time.Hour), nil)

		// Inject a SetEmailVerified failure.
		users.setEmailVerifiedErr = errInjected

		svc := newVerificationService(t, users, verifications, &spyMailer{}, nil)
		err := svc.VerifyEmail(context.Background(), "rb-token")

		// The call must fail.
		require.Error(t, err)
		assert.ErrorIs(t, err, errInjected)

		// User must NOT be email-verified.
		assert.False(t, users.byID[u.ID].EmailVerified, "email must not be verified after a SetEmailVerified failure")

		// In the sequential fallback path the fake MarkConsumed has already run; in the
		// transactional path both would be rolled back. Assert that the service returned
		// an error — the caller cannot proceed as if verification succeeded.
	})

	t.Run("MarkConsumed failure returns error without touching SetEmailVerified", func(t *testing.T) {
		t.Parallel()

		users := newFakeUserStore()
		u := seedUser(t, users, "mark-fail@example.com")
		verifications := newFakeVerificationStore()
		seedVerificationToken(t, verifications, u.ID, "mf-token", time.Now().UTC().Add(time.Hour), nil)

		// Inject a MarkConsumed failure.
		verifications.markConsumedErr = errInjected

		svc := newVerificationService(t, users, verifications, &spyMailer{}, nil)
		err := svc.VerifyEmail(context.Background(), "mf-token")

		// The call must fail and user must remain unverified.
		require.Error(t, err)
		assert.False(t, users.byID[u.ID].EmailVerified, "email must not be verified when MarkConsumed fails")
	})
}

// allowAllLimiter / denyAllLimiter exercise the resend rate-limit branches.
type allowAllLimiter struct{}

func (allowAllLimiter) Allow(_ context.Context, _ string) bool { return true }

type denyAllLimiter struct{}

func (denyAllLimiter) Allow(_ context.Context, _ string) bool { return false }

func TestAuthService_ResendVerification(t *testing.T) {
	t.Parallel()

	t.Run("unverified user → 1 send + prior tokens invalidated", func(t *testing.T) {
		t.Parallel()

		users := newFakeUserStore()
		u := seedUser(t, users, "resend@example.com")
		users.byID[u.ID].EmailVerified = false
		verifications := newFakeVerificationStore()
		mailer := &spyMailer{}

		svc := newVerificationService(t, users, verifications, mailer, allowAllLimiter{})
		svc.ResendVerification(context.Background(), "Resend@Example.com") // mixed case → normalized

		// The send is detached (FIX 2) so resend responses are constant-time; await
		// it deterministically (no time.Sleep) before asserting on the spy.
		svc.WaitForPendingSends()

		assert.Equal(t, 1, mailer.sendCount(), "exactly one verification email must be sent")
		assert.Equal(t, "resend@example.com", mailer.sentTo[0])
		assert.Contains(t, verifications.invalidatedUsers, u.ID, "prior outstanding tokens must be invalidated first")
	})

	t.Run("unknown email → 0 sends (no enumeration)", func(t *testing.T) {
		t.Parallel()

		users := newFakeUserStore()
		verifications := newFakeVerificationStore()
		mailer := &spyMailer{}

		svc := newVerificationService(t, users, verifications, mailer, allowAllLimiter{})
		svc.ResendVerification(context.Background(), "ghost@example.com")
		svc.WaitForPendingSends()

		assert.Equal(t, 0, mailer.sendCount(), "no email for an unknown address")
	})

	t.Run("already-verified user → 0 sends", func(t *testing.T) {
		t.Parallel()

		users := newFakeUserStore()
		u := seedUser(t, users, "done@example.com")
		users.byID[u.ID].EmailVerified = true
		verifications := newFakeVerificationStore()
		mailer := &spyMailer{}

		svc := newVerificationService(t, users, verifications, mailer, allowAllLimiter{})
		svc.ResendVerification(context.Background(), "done@example.com")
		svc.WaitForPendingSends()

		assert.Equal(t, 0, mailer.sendCount(), "verified accounts get no resend")
	})

	t.Run("rate-limited → 0 sends", func(t *testing.T) {
		t.Parallel()

		users := newFakeUserStore()
		u := seedUser(t, users, "throttled@example.com")
		users.byID[u.ID].EmailVerified = false
		verifications := newFakeVerificationStore()
		mailer := &spyMailer{}

		svc := newVerificationService(t, users, verifications, mailer, denyAllLimiter{})
		svc.ResendVerification(context.Background(), "throttled@example.com")
		svc.WaitForPendingSends()

		assert.Equal(t, 0, mailer.sendCount(), "throttled caller gets no email")
	})
}
