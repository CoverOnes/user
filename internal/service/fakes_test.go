package service_test

import (
	"context"
	"errors"
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
	createErr        error
	getByIDErr       error
	getByEmailErr    error
	updateProfileErr error
	bumpVersionErr   error
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
	u.KYCTier = tier

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

func (f *fakeRefreshTokenStore) MarkUsed(_ context.Context, id uuid.UUID, now time.Time) error {
	if f.markUsedErr != nil {
		return f.markUsedErr
	}
	if rt, ok := f.tokens[id]; ok {
		t := now
		rt.UsedAt = &t
		rt.RevokedAt = &t
	}

	return nil
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
