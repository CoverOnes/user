// Package service implements the business logic for the user service.
package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"log/slog"
	"net/netip"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/CoverOnes/user/internal/auth/jwt"
	"github.com/CoverOnes/user/internal/auth/password"
	"github.com/CoverOnes/user/internal/auth/refresh"
	"github.com/CoverOnes/user/internal/domain"
	"github.com/CoverOnes/user/internal/identity"
	"github.com/CoverOnes/user/internal/store"
	"github.com/google/uuid"
)

// maxCompanyNameRunes bounds the company name length (rune count) to match the
// handler's binding (max=200) and cap the worst-case ~1 MB-string DoS (P1).
const maxCompanyNameRunes = 200

// verificationTokenTTL is how long an email-verification token stays valid.
const verificationTokenTTL = 24 * time.Hour

// verificationTokenBytes is the entropy of a raw verification token (256 bits).
const verificationTokenBytes = 32

// Transactioner is implemented by store backends that support DB transactions.
// The AuthService uses it for Register where user + company + verification token
// must be created atomically.
type Transactioner interface {
	WithTx(ctx context.Context, fn func(
		ctx context.Context,
		users store.UserStore,
		companies store.CompanyStore,
		verifications store.EmailVerificationTokenStore,
	) error) error
}

// Encryptor encrypts/decrypts HIGH-sensitivity PII (legal name, national ID).
// Implemented by internal/crypto/pii.Encryptor; an interface here keeps the
// service testable and the dependency injectable (mirrors the limiter chain).
type Encryptor interface {
	Encrypt(plaintext string) ([]byte, error)
	Decrypt(data []byte) (string, error)
}

// Mailer sends the post-register verification email. Implemented by
// internal/mailer; a spy is used in tests.
type Mailer interface {
	SendVerification(ctx context.Context, to, token string) error
}

// EmailRateLimiter throttles per-email actions (resend-verification). Same
// fail-safe contract as LoginRateLimiter.
type EmailRateLimiter interface {
	Allow(ctx context.Context, normalizedEmail string) bool
}

// LoginRateLimiter throttles login attempts per normalized email (credential-stuffing
// defense, in addition to the IP-level middleware limiter). Implementations MUST fail
// safe — returning true when the backing store is unavailable so a Redis outage cannot
// lock every account out of login.
type LoginRateLimiter interface {
	// Allow reports whether a login attempt for the given normalized email is admitted.
	Allow(ctx context.Context, normalizedEmail string) bool
}

// AuthService handles authentication business logic.
type AuthService struct {
	users         store.UserStore
	companies     store.CompanyStore
	refreshTokens store.RefreshTokenStore
	verifications store.EmailVerificationTokenStore // may be nil (verify/resend disabled)
	tx            Transactioner                     // may be nil for stores that don't support tx
	loginLimiter  LoginRateLimiter                  // may be nil (per-email login throttling disabled)
	resendLimiter EmailRateLimiter                  // may be nil (resend throttling disabled)
	encryptor     Encryptor                         // may be nil (no PII encryption — dev/test legacy path)
	mailer        Mailer                            // may be nil (no verification email sent)
	signer        *jwt.Signer
	accessTTL     time.Duration
	refreshTTLH   int

	// sendWG tracks in-flight detached verification-email goroutines. The
	// post-commit (Register) and resend sends run on a background context so all
	// responses return in constant DB-only time — synchronous SMTP would make
	// "exists+unverified" measurably slower than "unknown/verified" (timing
	// enumeration oracle, FIX 2). WaitForPendingSends lets a graceful shutdown —
	// and tests — block until every dispatched send has finished.
	sendWG sync.WaitGroup
}

// NewAuthService creates an AuthService with injected dependencies.
// tx may be nil; when nil, Register falls back to two sequential Exec calls (dev/test only).
func NewAuthService(
	users store.UserStore,
	companies store.CompanyStore,
	refreshTokens store.RefreshTokenStore,
	tx Transactioner,
	signer *jwt.Signer,
	accessTTL time.Duration,
	refreshTTLHours int,
) *AuthService {
	return &AuthService{
		users:         users,
		companies:     companies,
		refreshTokens: refreshTokens,
		tx:            tx,
		signer:        signer,
		accessTTL:     accessTTL,
		refreshTTLH:   refreshTTLHours,
	}
}

// WithLoginRateLimiter installs a per-email login rate limiter and returns the
// service for chaining. Passing nil (or never calling this) leaves per-email
// throttling disabled. Kept separate from the constructor so existing call sites
// and tests are unaffected.
func (s *AuthService) WithLoginRateLimiter(l LoginRateLimiter) *AuthService {
	s.loginLimiter = l

	return s
}

// WithVerification installs the email-verification dependencies (token store,
// encryptor, mailer, and the resend rate limiter) and returns the service for
// chaining. Mirrors WithLoginRateLimiter so existing call sites / tests that do
// not need verification are unaffected. Any argument may be nil to disable the
// corresponding capability.
func (s *AuthService) WithVerification(
	verifications store.EmailVerificationTokenStore,
	encryptor Encryptor,
	mailer Mailer,
	resendLimiter EmailRateLimiter,
) *AuthService {
	s.verifications = verifications
	s.encryptor = encryptor
	s.mailer = mailer
	s.resendLimiter = resendLimiter

	return s
}

// RegisterInput carries the validated registration request.
type RegisterInput struct {
	Email       string
	Password    string
	DisplayName string
	AccountType string
	// LegalName is the user's real name (required for BOTH account types).
	LegalName string
	// NationalID is the TW national ID (required + checksum-validated for PERSONAL;
	// optional/ignored for COMPANY — company identity is KYC tier-2, handled later).
	NationalID  string
	CompanyName string
}

// RegisterOutput carries the created user.
type RegisterOutput struct {
	User *domain.User
}

// Register creates a new PENDING_VERIFICATION user (real-name + email-verify
// flow, Increment 1). In one DB transaction it inserts the user (with encrypted
// legal name and, for PERSONAL, encrypted national ID), the company row (COMPANY),
// and a HASHED verification token. AFTER the tx commits it dispatches the
// verification email on a DETACHED background goroutine; an SMTP failure is logged
// (slog.Warn) and the call still returns the user — the account exists and the
// user can resend. The user is NEVER rolled back on email failure, and the send
// runs off the request path so the response time carries no SMTP-latency signal.
//
//nolint:gocritic // hugeParam: RegisterInput value-copy is intentional; pointer indirection at call sites would obscure ownership semantics
func (s *AuthService) Register(ctx context.Context, in RegisterInput) (*RegisterOutput, error) {
	if !domain.ValidAccountTypes[in.AccountType] {
		return nil, domain.ErrInvalidCredentials // reuse generic error to avoid enumeration
	}

	if in.AccountType == domain.AccountTypeCompany && strings.TrimSpace(in.CompanyName) == "" {
		return nil, domain.ErrCompanyNameRequired
	}

	// Defense-in-depth rune-length guard (P1): the handler binding caps companyName at
	// max=200, but the service is reachable independently (tests / internal callers).
	if utf8.RuneCountInString(in.CompanyName) > maxCompanyNameRunes {
		return nil, domain.ErrCompanyNameTooLong
	}

	// Identity validation. legalName required for BOTH types; nationalId required +
	// checksum-validated for PERSONAL only. Validation errors NEVER echo the PII value.
	if err := identity.ValidateLegalName(in.LegalName); err != nil {
		return nil, err
	}

	if in.AccountType == domain.AccountTypePersonal {
		if err := identity.ValidateTWNationalID(in.NationalID); err != nil {
			return nil, err
		}
	}

	if err := password.MeetsComplexity(in.Password); err != nil {
		return nil, domain.ErrWeakPassword
	}

	hash, err := password.Hash(in.Password, password.DefaultParams)
	if err != nil {
		return nil, err
	}

	// Encrypt PII before it touches the DB. The encryptor is required for register
	// in every non-legacy path (config fail-fast guarantees it outside tests).
	legalNameEnc, nationalIDEnc, err := s.encryptIdentity(in)
	if err != nil {
		// Encryption failure must not silently persist plaintext — fail the register.
		slog.Error("register: PII encryption failed") // no PII / no err detail in the message
		return nil, err
	}

	now := time.Now().UTC()
	userID := uuid.New()

	u := &domain.User{
		ID:            userID,
		Email:         strings.ToLower(strings.TrimSpace(in.Email)),
		PasswordHash:  hash,
		DisplayName:   in.DisplayName,
		AccountType:   in.AccountType,
		KYCTier:       0,
		Status:        domain.UserStatusPendingVerification,
		EmailVerified: false,
		LegalNameEnc:  legalNameEnc,
		NationalIDEnc: nationalIDEnc,
		TokenVersion:  0,
		CreatedAt:     now,
		UpdatedAt:     now,
	}

	// Mint a verification token (raw delivered by email, hash persisted).
	rawToken, tokenHash, err := newVerificationToken()
	if err != nil {
		return nil, err
	}

	vt := &domain.EmailVerificationToken{
		ID:        uuid.New(),
		UserID:    userID,
		TokenHash: tokenHash,
		ExpiresAt: now.Add(verificationTokenTTL),
		CreatedAt: now,
	}

	if err := s.persistRegistration(ctx, u, vt, in, now); err != nil {
		return nil, err
	}

	// AFTER commit: send the verification email on a DETACHED goroutine. The user
	// is already persisted and committed above, so an SMTP failure cannot roll it
	// back — Register returns the user (201) regardless. Detaching the send (rather
	// than blocking) also keeps the response in constant DB-only time, matching the
	// resend path and removing an SMTP-latency signal (FIX 2). The original request
	// ctx may be canceled the moment Register returns, so the send uses a background
	// context bounded by the mailer's own SendTimeout.
	//
	//nolint:contextcheck // intentional detach: the send goroutine MUST NOT inherit the
	// request ctx (it is canceled when the handler returns) — backend-security-design §5.
	s.dispatchVerificationEmail(u.Email, rawToken)

	return &RegisterOutput{User: u}, nil
}

// encryptIdentity encrypts the legal name (always) and national ID (PERSONAL only).
// Returns (legalNameEnc, nationalIDEnc, error). nationalIDEnc is nil for COMPANY.
//
//nolint:gocritic // hugeParam: RegisterInput value-copy mirrors Register's signature
func (s *AuthService) encryptIdentity(in RegisterInput) (legalNameEnc, nationalIDEnc []byte, err error) {
	if s.encryptor == nil {
		// No encryptor wired — only reachable in legacy unit tests that don't set it.
		// The boot-time config guard prevents this in any real deployment.
		return nil, nil, nil
	}

	legalNameEnc, err = s.encryptor.Encrypt(in.LegalName)
	if err != nil {
		return nil, nil, err
	}

	if in.AccountType == domain.AccountTypePersonal {
		nationalIDEnc, err = s.encryptor.Encrypt(in.NationalID)
		if err != nil {
			return nil, nil, err
		}
	}

	return legalNameEnc, nationalIDEnc, nil
}

// persistRegistration creates the user, (COMPANY) company, and verification token.
// Uses a single tx when available; otherwise falls back to sequential calls
// (test backends without tx support — logic, not atomicity, is exercised there).
//
//nolint:gocritic // hugeParam: RegisterInput value-copy mirrors Register's signature
func (s *AuthService) persistRegistration(
	ctx context.Context,
	u *domain.User,
	vt *domain.EmailVerificationToken,
	in RegisterInput,
	now time.Time,
) error {
	if s.tx != nil {
		return s.tx.WithTx(ctx, func(
			txCtx context.Context,
			txUsers store.UserStore,
			txCompanies store.CompanyStore,
			txVerifications store.EmailVerificationTokenStore,
		) error {
			if txErr := txUsers.Create(txCtx, u); txErr != nil {
				return txErr
			}

			if in.AccountType == domain.AccountTypeCompany {
				if txErr := txCompanies.Create(txCtx, newCompany(in.CompanyName, u.ID, now)); txErr != nil {
					return txErr
				}
			}

			return txVerifications.Create(txCtx, vt)
		})
	}

	// Sequential fallback (no tx support).
	if createErr := s.users.Create(ctx, u); createErr != nil {
		return createErr
	}

	if in.AccountType == domain.AccountTypeCompany {
		if coErr := s.companies.Create(ctx, newCompany(in.CompanyName, u.ID, now)); coErr != nil {
			return coErr
		}
	}

	if s.verifications != nil {
		if vErr := s.verifications.Create(ctx, vt); vErr != nil {
			return vErr
		}
	}

	return nil
}

// dispatchVerificationEmail sends the verification email on a DETACHED goroutine
// so the caller (Register / ResendVerification) returns in constant DB-only time.
// Blocking on the synchronous SMTP round-trip would make "exists+unverified"
// responses measurably slower than "unknown/verified" ones — a latency
// enumeration oracle (FIX 2). A background context is used (the request ctx is
// canceled the instant the handler returns); the send is bounded by the mailer's
// own SendTimeout, so it cannot leak a goroutine indefinitely. The in-flight send
// is tracked on sendWG so graceful shutdown and tests can await completion.
func (s *AuthService) dispatchVerificationEmail(email, rawToken string) {
	if s.mailer == nil {
		return
	}

	s.sendWG.Add(1)

	go func() {
		defer s.sendWG.Done()

		// Detached: do NOT inherit the request context (it is canceled when the
		// handler returns). The mailer bounds the send with its own SendTimeout.
		s.sendVerificationEmail(context.Background(), email, rawToken)
	}()
}

// sendVerificationEmail performs the synchronous best-effort send. A nil mailer or
// an SMTP error is logged and swallowed — the user is already persisted, so the
// account exists and the user can resend; we never roll back on email failure.
func (s *AuthService) sendVerificationEmail(ctx context.Context, email, rawToken string) {
	if s.mailer == nil {
		return
	}

	if err := s.mailer.SendVerification(ctx, email, rawToken); err != nil {
		// Do NOT roll back the user; the account is created and can resend.
		slog.Warn("verification email send failed", "err", err)
	}
}

// WaitForPendingSends blocks until all detached verification-email goroutines
// dispatched so far have completed. It is used by graceful shutdown to avoid
// dropping in-flight sends, and by tests to await an async send deterministically
// (no time.Sleep). Safe to call concurrently with new dispatches.
func (s *AuthService) WaitForPendingSends() {
	s.sendWG.Wait()
}

// newCompany builds a Company domain object for the register flow.
func newCompany(name string, ownerUserID uuid.UUID, now time.Time) *domain.Company {
	return &domain.Company{
		ID:          uuid.New(),
		Name:        name,
		OwnerUserID: ownerUserID,
		Status:      domain.CompanyStatusActive,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
}

// newVerificationToken returns (rawToken, sha256Hash, error). The raw token is
// emailed; only its SHA-256 hash is stored.
func newVerificationToken() (raw string, hash []byte, err error) {
	b := make([]byte, verificationTokenBytes)
	if _, err := rand.Read(b); err != nil {
		return "", nil, err
	}

	raw = base64.RawURLEncoding.EncodeToString(b)
	sum := sha256.Sum256([]byte(raw))

	return raw, sum[:], nil
}

// LoginInput carries the login request data.
type LoginInput struct {
	Email             string
	Password          string
	DeviceFingerprint *string
	IPAddr            netip.Addr
	UserAgent         *string
}

// TokenPair is the response after successful login or refresh.
type TokenPair struct {
	AccessToken  string
	RefreshToken string
	ExpiresIn    int // seconds
}

// Login verifies credentials and issues a new token family.
func (s *AuthService) Login(ctx context.Context, in LoginInput) (*TokenPair, error) {
	normalizedEmail := strings.ToLower(strings.TrimSpace(in.Email))

	// Per-email login rate limit (credential-stuffing defense, P1). Checked before the
	// DB lookup and the (expensive) argon2 verification so a spray attack is throttled
	// early. The limiter fails safe (allows) when Redis is unavailable.
	if s.loginLimiter != nil && !s.loginLimiter.Allow(ctx, normalizedEmail) {
		return nil, domain.ErrLoginRateLimited
	}

	u, err := s.users.GetByEmail(ctx, normalizedEmail)
	if err != nil {
		// Map not-found to invalid-credentials to prevent user enumeration.
		if errors.Is(err, domain.ErrNotFound) {
			return nil, domain.ErrInvalidCredentials
		}

		return nil, err
	}

	// Verify the password BEFORE revealing account status (enumeration mitigation, P1).
	// An attacker who does not know the password must receive the same generic
	// INVALID_CREDENTIALS as for a wrong password / unknown email, so they cannot probe
	// which accounts exist and are suspended. Only a caller who proves knowledge of the
	// correct password is told the account is suspended (legitimate-user UX preserved).
	ok, err := password.Verify(in.Password, u.PasswordHash)
	if err != nil || !ok {
		return nil, domain.ErrInvalidCredentials
	}

	// Login is allowed for ACTIVE and PENDING_VERIFICATION; only SUSPENDED is
	// rejected (403). The access token carries email_verified from the FRESH
	// users.email_verified, so write routes gated by RequireEmailVerified stay
	// blocked until the user verifies — but the user can still authenticate and
	// (e.g.) update their profile while pending.
	if u.Status == domain.UserStatusSuspended {
		return nil, domain.ErrAccountSuspended
	}

	return s.issueTokenPair(ctx, u, nil, uuid.New(), in.DeviceFingerprint, in.IPAddr, in.UserAgent)
}

// VerifyEmail consumes a single-use verification token: it hashes the presented
// raw token, looks up an unconsumed + unexpired row, atomically marks it consumed,
// and sets users.email_verified = true. ALL failure modes (not-found / expired /
// already-consumed) return the single generic ErrInvalidVerificationToken — no
// oracle. Issues no tokens.
func (s *AuthService) VerifyEmail(ctx context.Context, rawToken string) error {
	if s.verifications == nil {
		return domain.ErrInvalidVerificationToken
	}

	if strings.TrimSpace(rawToken) == "" {
		return domain.ErrInvalidVerificationToken
	}

	sum := sha256.Sum256([]byte(rawToken))

	vt, err := s.verifications.GetByHash(ctx, sum[:])
	if err != nil {
		// GetByHash already maps not-found to ErrInvalidVerificationToken.
		return err
	}

	// Expired or already consumed → same generic error.
	if vt.ConsumedAt != nil || time.Now().UTC().After(vt.ExpiresAt) {
		return domain.ErrInvalidVerificationToken
	}

	// Atomic single-use: MarkConsumed only updates when consumed_at IS NULL, so a
	// concurrent double-verify loses the race and gets ErrInvalidVerificationToken.
	now := time.Now().UTC()
	if err := s.verifications.MarkConsumed(ctx, vt.ID, now); err != nil {
		return err
	}

	if err := s.users.SetEmailVerified(ctx, vt.UserID); err != nil {
		return err
	}

	return nil
}

// ResendVerification re-sends a verification email for the given address. It is
// enumeration-safe: the caller ALWAYS gets the same 202 regardless of whether the
// email exists or its state, so this method returns no error to drive a different
// response. It only actually sends when the email maps to an unverified user, and
// it invalidates that user's prior outstanding tokens first. A per-email rate
// limit (resendLimiter) caps abuse; a throttled caller is silently dropped (still
// 202 at the handler).
func (s *AuthService) ResendVerification(ctx context.Context, email string) {
	normalizedEmail := strings.ToLower(strings.TrimSpace(email))

	if s.verifications == nil || s.mailer == nil {
		return
	}

	if s.resendLimiter != nil && !s.resendLimiter.Allow(ctx, normalizedEmail) {
		// Over the 3/hour cap — silently drop (handler still returns 202).
		return
	}

	u, err := s.users.GetByEmail(ctx, normalizedEmail)
	if err != nil {
		// Unknown email → no send, no leak. (Not-found and any other store error
		// are both swallowed; the handler's 202 is unconditional.)
		return
	}

	if u.EmailVerified {
		// Already verified → nothing to do.
		return
	}

	now := time.Now().UTC()

	// Invalidate prior outstanding tokens so only the newest token is usable.
	if err := s.verifications.InvalidateForUser(ctx, u.ID, now); err != nil {
		slog.Warn("resend: invalidate prior tokens failed", "err", err, "userId", u.ID)
		return
	}

	rawToken, tokenHash, err := newVerificationToken()
	if err != nil {
		slog.Warn("resend: token generation failed", "err", err, "userId", u.ID)
		return
	}

	vt := &domain.EmailVerificationToken{
		ID:        uuid.New(),
		UserID:    u.ID,
		TokenHash: tokenHash,
		ExpiresAt: now.Add(verificationTokenTTL),
		CreatedAt: now,
	}

	if err := s.verifications.Create(ctx, vt); err != nil {
		slog.Warn("resend: persist token failed", "err", err, "userId", u.ID)
		return
	}

	// Detached send so EVERY resend response returns in constant DB-only time
	// (FIX 2): a synchronous SMTP round-trip here would make this "exists+unverified"
	// path measurably slower than the unknown/verified/rate-limited paths above,
	// which all return without any SMTP call — a latency enumeration oracle.
	//
	//nolint:contextcheck // intentional detach: the send goroutine MUST NOT inherit the
	// request ctx (it is canceled when the handler returns) — backend-security-design §5.
	s.dispatchVerificationEmail(u.Email, rawToken)
}

// RefreshInput carries the refresh request.
type RefreshInput struct {
	RawToken          string
	DeviceFingerprint *string
	IPAddr            netip.Addr
	UserAgent         *string
}

// Refresh validates the presented refresh token and rotates it.
func (s *AuthService) Refresh(ctx context.Context, in RefreshInput) (*TokenPair, error) {
	parsed, err := refresh.Parse(in.RawToken)
	if err != nil {
		return nil, domain.ErrInvalidRefresh
	}

	rt, err := s.refreshTokens.GetByID(ctx, parsed.ID)
	if err != nil {
		return nil, domain.ErrInvalidRefresh
	}

	// Constant-time compare token hash.
	if !subtleEqual(rt.TokenHash, parsed.Hash) {
		return nil, domain.ErrInvalidRefresh
	}

	now := time.Now().UTC()

	// Check expiry before the database round-trip.
	if now.After(rt.ExpiresAt) {
		return nil, domain.ErrRefreshExpired
	}

	// Log device fingerprint anomaly (MVP: warn only, no step-up).
	if in.DeviceFingerprint != nil && rt.DeviceFingerprint != nil &&
		*in.DeviceFingerprint != *rt.DeviceFingerprint {
		slog.Warn(
			"refresh.device_fingerprint_mismatch",
			"userId", rt.UserID,
			"familyId", rt.FamilyID,
		)
	}

	// Atomic CAS: only one goroutine racing on the same token can flip
	// used_at from NULL to a timestamp. The loser (ok=false) detects reuse,
	// revokes the family, and returns ErrRefreshReuse — defeating replay even
	// under concurrent requests. This replaces the pre-check on rt.UsedAt,
	// which was a TOCTOU: two goroutines could both read used_at=nil, then
	// both succeed the old unconditional UPDATE, and never trigger revocation.
	ok, err := s.refreshTokens.MarkUsed(ctx, rt.ID, now)
	if err != nil {
		return nil, err
	}

	if !ok {
		// CAS lost: another concurrent request already consumed this token.
		slog.Warn(
			"refresh.reuse_detected",
			"userId", rt.UserID,
			"familyId", rt.FamilyID,
		)

		if revokeErr := s.refreshTokens.RevokeFamily(ctx, rt.FamilyID, now); revokeErr != nil {
			slog.Error("failed to revoke token family on reuse", "err", revokeErr)
		}

		return nil, domain.ErrRefreshReuse
	}

	// Fetch fresh user data.
	u, err := s.users.GetByID(ctx, rt.UserID)
	if err != nil {
		return nil, domain.ErrInvalidRefresh
	}

	// Enforce token_version server-side (M1 fix): compare the version stored in
	// the refresh_tokens row at issuance time against the FRESH users.token_version
	// loaded from DB above. The client supplies no version information — the stored
	// value is authoritative, preventing version-laundering / logout-all bypass.
	// NOTE: the bump trigger (a logout-all / revoke-all-sessions endpoint that
	// increments users.token_version) is a pending follow-up — this enforcement
	// path is wired and tested, but no endpoint increments the version yet.
	if rt.TokenVersion != u.TokenVersion {
		slog.Warn(
			"refresh.token_version_mismatch",
			"userId", u.ID,
			"storedVersion", rt.TokenVersion,
			"userVersion", u.TokenVersion,
		)
		// Revoke the entire family to force re-login.
		if revokeErr := s.refreshTokens.RevokeFamily(ctx, rt.FamilyID, now); revokeErr != nil {
			slog.Error("failed to revoke token family on version mismatch", "err", revokeErr)
		}
		return nil, domain.ErrInvalidRefresh
	}

	prevID := rt.ID

	return s.issueTokenPair(ctx, u, &prevID, rt.FamilyID, in.DeviceFingerprint, in.IPAddr, in.UserAgent)
}

// Logout revokes the presented refresh token's family.
// It verifies the token_hash against the stored record BEFORE revoking, so that
// a random token ID cannot be used to revoke another user's session family (F1).
func (s *AuthService) Logout(ctx context.Context, rawToken string) error {
	parsed, err := refresh.Parse(rawToken)
	if err != nil {
		return domain.ErrInvalidRefresh
	}

	rt, err := s.refreshTokens.GetByID(ctx, parsed.ID)
	if err != nil {
		return domain.ErrInvalidRefresh
	}

	// Verify token hash binding before acting — prevents a caller with only
	// the token ID from revoking a family they don't own.
	if !subtleEqual(rt.TokenHash, parsed.Hash) {
		return domain.ErrInvalidRefresh
	}

	now := time.Now().UTC()

	return s.refreshTokens.RevokeFamily(ctx, rt.FamilyID, now)
}

// LogoutAll bumps the user's token_version, which causes all currently-issued
// refresh tokens to fail the server-side version check on next use.
// The caller is responsible for ensuring userID is authenticated (derived from token sub).
func (s *AuthService) LogoutAll(ctx context.Context, userID uuid.UUID) error {
	_, err := s.users.BumpTokenVersion(ctx, userID)
	if err != nil {
		return err
	}

	slog.Info("auth.logout_all", "userId", userID)

	return nil
}

func (s *AuthService) issueTokenPair(
	ctx context.Context,
	u *domain.User,
	prevID *uuid.UUID,
	familyID uuid.UUID,
	deviceFingerprint *string,
	ipAddr netip.Addr,
	userAgent *string,
) (*TokenPair, error) {
	// EmailVerified is read from the FRESH user (Login/Refresh both load it from DB
	// before calling here), so a just-verified user's next token lifts the gate.
	accessToken, err := s.signer.Issue(u.ID.String(), u.AccountType, u.KYCTier, u.TokenVersion, u.EmailVerified)
	if err != nil {
		return nil, err
	}

	tok, err := refresh.Generate()
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	rt := &domain.RefreshToken{
		ID:                tok.ID,
		UserID:            u.ID,
		FamilyID:          familyID,
		TokenHash:         tok.Hash,
		PrevID:            prevID,
		DeviceFingerprint: deviceFingerprint,
		IPAddr:            ipAddr,
		UserAgent:         userAgent,
		ExpiresAt:         now.Add(time.Duration(s.refreshTTLH) * time.Hour),
		CreatedAt:         now,
		// Snapshot the user's current token_version into the refresh token row so
		// that server-side enforcement at refresh time requires no client input (M1).
		TokenVersion: u.TokenVersion,
	}

	if err := s.refreshTokens.Create(ctx, rt); err != nil {
		return nil, err
	}

	return &TokenPair{
		AccessToken:  accessToken,
		RefreshToken: tok.Raw,
		ExpiresIn:    int(s.accessTTL.Seconds()),
	}, nil
}

// subtleEqual performs a constant-time byte slice comparison using crypto/subtle
// to prevent timing side-channels (F14).
func subtleEqual(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}
