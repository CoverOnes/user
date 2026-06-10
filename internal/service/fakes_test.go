package service_test

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/CoverOnes/user/internal/domain"
	"github.com/google/uuid"
)

// errInjected is a generic backend error used to exercise store-failure paths.
var errInjected = errors.New("injected store error")

// --- fakeUserStore ---

// fakeUserStore is an in-memory UserStore with per-method error injection so unit
// tests can drive both happy and store-failure paths without a real DB.
type fakeUserStore struct {
	byID    map[uuid.UUID]*domain.User
	byEmail map[string]*domain.User

	// error-injection hooks (nil = no error).
	createErr           error
	getByIDErr          error
	getByEmailErr       error
	updateProfileErr    error
	bumpVersionErr      error
	setEmailVerifiedErr error
	setPendingSecretErr error
	enableMFAErr        error
	disableMFAErr       error
	setBackupCodesErr   error
}

func newFakeUserStore() *fakeUserStore {
	return &fakeUserStore{
		byID:    make(map[uuid.UUID]*domain.User),
		byEmail: make(map[string]*domain.User),
	}
}

func (f *fakeUserStore) put(u *domain.User) {
	cp := *u
	f.byID[u.ID] = &cp
	f.byEmail[u.Email] = &cp
}

func (f *fakeUserStore) Create(_ context.Context, u *domain.User) error {
	if f.createErr != nil {
		return f.createErr
	}
	if _, exists := f.byEmail[u.Email]; exists {
		return domain.ErrEmailTaken
	}
	f.put(u)

	return nil
}

func (f *fakeUserStore) GetByID(_ context.Context, id uuid.UUID) (*domain.User, error) {
	if f.getByIDErr != nil {
		return nil, f.getByIDErr
	}
	u, ok := f.byID[id]
	if !ok {
		return nil, domain.ErrNotFound
	}

	return u, nil
}

func (f *fakeUserStore) GetByEmail(_ context.Context, email string) (*domain.User, error) {
	if f.getByEmailErr != nil {
		return nil, f.getByEmailErr
	}
	u, ok := f.byEmail[email]
	if !ok {
		return nil, domain.ErrNotFound
	}

	return u, nil
}

func (f *fakeUserStore) UpdateProfile(_ context.Context, id uuid.UUID, displayName string, avatarURL *string) error {
	if f.updateProfileErr != nil {
		return f.updateProfileErr
	}
	u, ok := f.byID[id]
	if !ok {
		return domain.ErrNotFound
	}
	u.DisplayName = displayName
	u.AvatarURL = avatarURL

	return nil
}

func (f *fakeUserStore) UpdateKYCTier(_ context.Context, id uuid.UUID, tier int16) error {
	u, ok := f.byID[id]
	if !ok {
		return domain.ErrNotFound
	}
	// Mirror the monotonic Postgres CAS: only advance tier, never lower it.
	if tier > u.KYCTier {
		u.KYCTier = tier
	}

	return nil
}

func (f *fakeUserStore) BumpTokenVersion(_ context.Context, id uuid.UUID) (int, error) {
	if f.bumpVersionErr != nil {
		return 0, f.bumpVersionErr
	}
	u, ok := f.byID[id]
	if !ok {
		return 0, domain.ErrNotFound
	}
	u.TokenVersion++

	return u.TokenVersion, nil
}

func (f *fakeUserStore) SetEmailVerified(_ context.Context, id uuid.UUID) error {
	if f.setEmailVerifiedErr != nil {
		return f.setEmailVerifiedErr
	}
	u, ok := f.byID[id]
	if !ok {
		return domain.ErrNotFound
	}
	u.EmailVerified = true
	if u.KYCTier < 1 {
		u.KYCTier = 1
	}

	return nil
}

func (f *fakeUserStore) SetPendingTOTPSecret(_ context.Context, id uuid.UUID, secretEnc []byte) error {
	if f.setPendingSecretErr != nil {
		return f.setPendingSecretErr
	}
	u, ok := f.byID[id]
	if !ok {
		return domain.ErrNotFound
	}
	u.TOTPSecretEnc = secretEnc

	return nil
}

func (f *fakeUserStore) EnableMFA(_ context.Context, id uuid.UUID, backupCodesEnc []byte, enrolledAt time.Time) error {
	if f.enableMFAErr != nil {
		return f.enableMFAErr
	}
	u, ok := f.byID[id]
	if !ok {
		return domain.ErrNotFound
	}
	// Mirror the store's ATOMIC conditional UPDATE (WHERE mfa_enabled = false): a second
	// EnableMFA on an already-enabled row is rejected and does NOT overwrite the persisted
	// backup codes, so the loser of a confirm-twice race gets ErrMFAAlreadyEnabled.
	if u.MFAEnabled {
		return domain.ErrMFAAlreadyEnabled
	}
	u.MFAEnabled = true
	u.MFABackupCodesEnc = backupCodesEnc
	u.MFAEnrolledAt = &enrolledAt

	return nil
}

func (f *fakeUserStore) DisableMFA(_ context.Context, id uuid.UUID) error {
	if f.disableMFAErr != nil {
		return f.disableMFAErr
	}
	u, ok := f.byID[id]
	if !ok {
		return domain.ErrNotFound
	}
	u.MFAEnabled = false
	u.TOTPSecretEnc = nil
	u.MFABackupCodesEnc = nil
	u.MFAEnrolledAt = nil

	return nil
}

func (f *fakeUserStore) SetMFABackupCodes(_ context.Context, id uuid.UUID, backupCodesEnc []byte) error {
	if f.setBackupCodesErr != nil {
		return f.setBackupCodesErr
	}
	u, ok := f.byID[id]
	if !ok {
		return domain.ErrNotFound
	}
	u.MFABackupCodesEnc = backupCodesEnc

	return nil
}

// --- fakeCompanyStore ---

type fakeCompanyStore struct {
	createErr error
	created   []*domain.Company
}

func (f *fakeCompanyStore) Create(_ context.Context, c *domain.Company) error {
	if f.createErr != nil {
		return f.createErr
	}
	f.created = append(f.created, c)

	return nil
}

func (f *fakeCompanyStore) GetByID(_ context.Context, _ uuid.UUID) (*domain.Company, error) {
	return nil, domain.ErrNotFound
}

// --- fakeRefreshTokenStore ---

type fakeRefreshTokenStore struct {
	tokens map[uuid.UUID]*domain.RefreshToken

	createErr       error
	getByIDErr      error
	markUsedErr     error
	revokeFamilyErr error

	revokedFamilies []uuid.UUID
}

func newFakeRefreshTokenStore() *fakeRefreshTokenStore {
	return &fakeRefreshTokenStore{tokens: make(map[uuid.UUID]*domain.RefreshToken)}
}

func (f *fakeRefreshTokenStore) Create(_ context.Context, rt *domain.RefreshToken) error {
	if f.createErr != nil {
		return f.createErr
	}
	cp := *rt
	f.tokens[rt.ID] = &cp

	return nil
}

func (f *fakeRefreshTokenStore) GetByID(_ context.Context, id uuid.UUID) (*domain.RefreshToken, error) {
	if f.getByIDErr != nil {
		return nil, f.getByIDErr
	}
	rt, ok := f.tokens[id]
	if !ok {
		return nil, domain.ErrInvalidRefresh
	}

	return rt, nil
}

func (f *fakeRefreshTokenStore) MarkUsed(_ context.Context, id uuid.UUID, now time.Time) (bool, error) {
	if f.markUsedErr != nil {
		return false, f.markUsedErr
	}

	rt, ok := f.tokens[id]
	if !ok {
		// Token does not exist — treat as already-used (CAS finds nothing to flip).
		return false, nil
	}

	// Mirror the Postgres CAS: only flip when used_at IS NULL.
	if rt.UsedAt != nil {
		return false, nil
	}

	t := now
	rt.UsedAt = &t
	rt.RevokedAt = &t

	return true, nil
}

func (f *fakeRefreshTokenStore) RevokeFamily(_ context.Context, familyID uuid.UUID, now time.Time) error {
	f.revokedFamilies = append(f.revokedFamilies, familyID)
	if f.revokeFamilyErr != nil {
		return f.revokeFamilyErr
	}
	for _, rt := range f.tokens {
		if rt.FamilyID == familyID && rt.RevokedAt == nil {
			t := now
			rt.RevokedAt = &t
		}
	}

	return nil
}

func (f *fakeRefreshTokenStore) familyRevoked(familyID uuid.UUID) bool {
	for _, id := range f.revokedFamilies {
		if id == familyID {
			return true
		}
	}

	return false
}

// --- fakeVerificationStore ---

// fakeVerificationStore is an in-memory EmailVerificationTokenStore keyed by the
// hex-encoded token hash, with per-method error injection.
type fakeVerificationStore struct {
	byHash map[string]*domain.EmailVerificationToken

	createErr        error
	getByHashErr     error
	markConsumedErr  error
	invalidateErr    error
	invalidatedUsers []uuid.UUID
}

func newFakeVerificationStore() *fakeVerificationStore {
	return &fakeVerificationStore{byHash: make(map[string]*domain.EmailVerificationToken)}
}

func (f *fakeVerificationStore) key(hash []byte) string { return string(hash) }

func (f *fakeVerificationStore) Create(_ context.Context, t *domain.EmailVerificationToken) error {
	if f.createErr != nil {
		return f.createErr
	}
	cp := *t
	f.byHash[f.key(t.TokenHash)] = &cp

	return nil
}

func (f *fakeVerificationStore) GetByHash(_ context.Context, tokenHash []byte) (*domain.EmailVerificationToken, error) {
	if f.getByHashErr != nil {
		return nil, f.getByHashErr
	}
	t, ok := f.byHash[f.key(tokenHash)]
	if !ok {
		return nil, domain.ErrInvalidVerificationToken
	}

	return t, nil
}

func (f *fakeVerificationStore) MarkConsumed(_ context.Context, id uuid.UUID, now time.Time) error {
	if f.markConsumedErr != nil {
		return f.markConsumedErr
	}
	for _, t := range f.byHash {
		if t.ID == id {
			if t.ConsumedAt != nil {
				// Already consumed → single-use guard (no oracle).
				return domain.ErrInvalidVerificationToken
			}
			c := now
			t.ConsumedAt = &c

			return nil
		}
	}

	return domain.ErrInvalidVerificationToken
}

func (f *fakeVerificationStore) InvalidateForUser(_ context.Context, userID uuid.UUID, now time.Time) error {
	f.invalidatedUsers = append(f.invalidatedUsers, userID)
	if f.invalidateErr != nil {
		return f.invalidateErr
	}
	for _, t := range f.byHash {
		if t.UserID == userID && t.ConsumedAt == nil {
			c := now
			t.ConsumedAt = &c
		}
	}

	return nil
}

// --- spyMailer ---

// spyMailer records SendVerification calls so tests can assert send count +
// recipient without touching SMTP.
type spyMailer struct {
	sendErr    error
	sentTo     []string
	sentTokens []string
}

func (m *spyMailer) SendVerification(_ context.Context, to, token string) error {
	m.sentTo = append(m.sentTo, to)
	m.sentTokens = append(m.sentTokens, token)

	return m.sendErr
}

func (m *spyMailer) sendCount() int { return len(m.sentTo) }

// --- noopEncryptor ---

// noopEncryptor is a deterministic in-memory Encryptor for service tests: it
// prefixes the plaintext so round-trips are verifiable without real AES.
type noopEncryptor struct {
	encryptErr error
}

func (e *noopEncryptor) Encrypt(plaintext string) ([]byte, error) {
	if e.encryptErr != nil {
		return nil, e.encryptErr
	}

	return append([]byte("enc:"), []byte(plaintext)...), nil
}

func (e *noopEncryptor) Decrypt(data []byte) (string, error) {
	return strings.TrimPrefix(string(data), "enc:"), nil
}
