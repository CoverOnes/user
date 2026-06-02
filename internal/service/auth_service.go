// Package service implements the business logic for the user service.
package service

import (
	"context"
	"crypto/subtle"
	"errors"
	"log/slog"
	"net/netip"
	"strings"
	"time"

	"github.com/CoverOnes/user/internal/auth/jwt"
	"github.com/CoverOnes/user/internal/auth/password"
	"github.com/CoverOnes/user/internal/auth/refresh"
	"github.com/CoverOnes/user/internal/domain"
	"github.com/CoverOnes/user/internal/store"
	"github.com/google/uuid"
)

// Transactioner is implemented by store backends that support DB transactions.
// The AuthService uses it only for Register where user+company must be atomic.
type Transactioner interface {
	WithTx(ctx context.Context, fn func(ctx context.Context, users store.UserStore, companies store.CompanyStore) error) error
}

// AuthService handles authentication business logic.
type AuthService struct {
	users         store.UserStore
	companies     store.CompanyStore
	refreshTokens store.RefreshTokenStore
	tx            Transactioner // may be nil for stores that don't support tx
	signer        *jwt.Signer
	accessTTL     time.Duration
	refreshTTLH   int
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

// RegisterInput carries the validated registration request.
type RegisterInput struct {
	Email       string
	Password    string
	DisplayName string
	AccountType string
	CompanyName string
}

// RegisterOutput carries the created user.
type RegisterOutput struct {
	User *domain.User
}

// Register creates a new user account and (for COMPANY) a linked company row.
// The user insert and company insert are wrapped in a single DB transaction so
// that a company creation failure rolls back the user row (F5).
//
//nolint:gocritic // hugeParam: RegisterInput value-copy is intentional; pointer indirection at call sites would obscure ownership semantics
func (s *AuthService) Register(ctx context.Context, in RegisterInput) (*RegisterOutput, error) {
	// Validate account type allowlist.
	if !domain.ValidAccountTypes[in.AccountType] {
		return nil, domain.ErrInvalidCredentials // reuse generic error to avoid enumeration
	}

	if in.AccountType == domain.AccountTypeCompany && strings.TrimSpace(in.CompanyName) == "" {
		return nil, domain.ErrCompanyNameRequired
	}

	// Password complexity.
	if err := password.MeetsComplexity(in.Password); err != nil {
		return nil, domain.ErrWeakPassword
	}

	hash, err := password.Hash(in.Password, password.DefaultParams)
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	userID := uuid.New()

	u := &domain.User{
		ID:           userID,
		Email:        strings.ToLower(strings.TrimSpace(in.Email)),
		PasswordHash: hash,
		DisplayName:  in.DisplayName,
		AccountType:  in.AccountType,
		KYCTier:      0,
		Status:       domain.UserStatusActive,
		TokenVersion: 0,
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	// Wrap user + company creation in a single atomic transaction.
	// When tx is nil (e.g. test mock backends without Tx support), fall back to
	// sequential calls — acceptable because tests exercise logic, not atomicity.
	if s.tx != nil {
		err = s.tx.WithTx(ctx, func(txCtx context.Context, txUsers store.UserStore, txCompanies store.CompanyStore) error {
			if txErr := txUsers.Create(txCtx, u); txErr != nil {
				return txErr
			}
			if in.AccountType == domain.AccountTypeCompany {
				co := &domain.Company{
					ID:          uuid.New(),
					Name:        in.CompanyName,
					OwnerUserID: userID,
					Status:      domain.CompanyStatusActive,
					CreatedAt:   now,
					UpdatedAt:   now,
				}
				return txCompanies.Create(txCtx, co)
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	} else {
		if createErr := s.users.Create(ctx, u); createErr != nil {
			return nil, createErr
		}
		if in.AccountType == domain.AccountTypeCompany {
			co := &domain.Company{
				ID:          uuid.New(),
				Name:        in.CompanyName,
				OwnerUserID: userID,
				Status:      domain.CompanyStatusActive,
				CreatedAt:   now,
				UpdatedAt:   now,
			}
			if coErr := s.companies.Create(ctx, co); coErr != nil {
				return nil, coErr
			}
		}
	}

	return &RegisterOutput{User: u}, nil
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
	u, err := s.users.GetByEmail(ctx, strings.ToLower(strings.TrimSpace(in.Email)))
	if err != nil {
		// Map not-found to invalid-credentials to prevent user enumeration.
		if errors.Is(err, domain.ErrNotFound) {
			return nil, domain.ErrInvalidCredentials
		}

		return nil, err
	}

	if u.Status == domain.UserStatusSuspended {
		return nil, domain.ErrAccountSuspended
	}

	ok, err := password.Verify(in.Password, u.PasswordHash)
	if err != nil || !ok {
		return nil, domain.ErrInvalidCredentials
	}

	return s.issueTokenPair(ctx, u, nil, uuid.New(), in.DeviceFingerprint, in.IPAddr, in.UserAgent)
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

	// Reuse detection: used_at already set means token was already consumed.
	if rt.UsedAt != nil || rt.RevokedAt != nil {
		slog.Warn("refresh.reuse_detected",
			"userId", rt.UserID,
			"familyId", rt.FamilyID,
		)

		// Revoke the entire family.
		if revokeErr := s.refreshTokens.RevokeFamily(ctx, rt.FamilyID, now); revokeErr != nil {
			slog.Error("failed to revoke token family on reuse", "err", revokeErr)
		}

		return nil, domain.ErrRefreshReuse
	}

	// Check expiry.
	if now.After(rt.ExpiresAt) {
		return nil, domain.ErrRefreshExpired
	}

	// Log device fingerprint anomaly (MVP: warn only, no step-up).
	if in.DeviceFingerprint != nil && rt.DeviceFingerprint != nil &&
		*in.DeviceFingerprint != *rt.DeviceFingerprint {
		slog.Warn("refresh.device_fingerprint_mismatch",
			"userId", rt.UserID,
			"familyId", rt.FamilyID,
		)
	}

	// Mark old token used.
	if err := s.refreshTokens.MarkUsed(ctx, rt.ID, now); err != nil {
		return nil, err
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
		slog.Warn("refresh.token_version_mismatch",
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

func (s *AuthService) issueTokenPair(
	ctx context.Context,
	u *domain.User,
	prevID *uuid.UUID,
	familyID uuid.UUID,
	deviceFingerprint *string,
	ipAddr netip.Addr,
	userAgent *string,
) (*TokenPair, error) {
	accessToken, err := s.signer.Issue(u.ID.String(), u.AccountType, u.KYCTier, u.TokenVersion)
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
