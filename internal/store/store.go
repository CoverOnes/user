// Package store defines the storage interfaces for the user service.
package store

import (
	"context"
	"net/netip"
	"time"

	"github.com/CoverOnes/user/internal/domain"
	"github.com/google/uuid"
)

// UserStore defines DB operations for user records.
type UserStore interface {
	Create(ctx context.Context, u *domain.User) error
	GetByID(ctx context.Context, id uuid.UUID) (*domain.User, error)
	GetByEmail(ctx context.Context, email string) (*domain.User, error)
	UpdateProfile(ctx context.Context, id uuid.UUID, displayName string, avatarURL *string) error
	// UpdateKYCTier sets kyc_tier for the given user (called by the Redis consumer on kyc.tier_changed).
	UpdateKYCTier(ctx context.Context, id uuid.UUID, tier int16) error
	// BumpTokenVersion atomically increments token_version and returns the new value.
	// Used by LogoutAll to invalidate all existing refresh tokens for a user.
	BumpTokenVersion(ctx context.Context, id uuid.UUID) (int, error)

	// SetEmailVerified sets users.email_verified = true and promotes the user to
	// at least Tier 1. Idempotent; returns ErrNotFound if no live row matches.
	SetEmailVerified(ctx context.Context, id uuid.UUID) error

	// SetPasswordHash replaces the stored password hash for the given user.
	// Returns ErrNotFound if no live row matches.
	SetPasswordHash(ctx context.Context, id uuid.UUID, hash string) error

	// SetPendingTOTPSecret stores the (encrypted) PENDING TOTP secret for enroll,
	// WITHOUT enabling MFA. Overwrites any prior pending/active secret so a re-enroll
	// supersedes the previous one. Returns ErrNotFound if no live row matches.
	SetPendingTOTPSecret(ctx context.Context, id uuid.UUID, secretEnc []byte) error

	// EnableMFA flips mfa_enabled = true, stores the (encrypted) backup codes, and
	// stamps mfa_enrolled_at. Called by confirm AFTER the code is verified against the
	// pending secret. Returns ErrNotFound if no live row matches.
	EnableMFA(ctx context.Context, id uuid.UUID, backupCodesEnc []byte, enrolledAt time.Time) error

	// DisableMFA clears mfa_enabled, totp_secret_enc, mfa_backup_codes_enc and
	// mfa_enrolled_at in one statement. Called by disable AFTER a current code is
	// verified. Returns ErrNotFound if no live row matches.
	DisableMFA(ctx context.Context, id uuid.UUID) error

	// SetMFABackupCodes overwrites only the (encrypted) backup codes for an
	// mfa-enabled user (e.g. when a backup code is consumed and the remaining set is
	// re-persisted). Returns ErrNotFound if no live row matches.
	SetMFABackupCodes(ctx context.Context, id uuid.UUID, backupCodesEnc []byte) error
}

// EmailVerificationTokenStore defines DB operations for single-use email
// verification tokens. Only the SHA-256 hash of a token is ever stored.
type EmailVerificationTokenStore interface {
	// Create inserts a new (hashed) verification token row.
	Create(ctx context.Context, t *domain.EmailVerificationToken) error

	// GetByHash fetches a token row by its SHA-256 hash. Returns
	// ErrInvalidVerificationToken when no row matches (no oracle).
	GetByHash(ctx context.Context, tokenHash []byte) (*domain.EmailVerificationToken, error)

	// MarkConsumed sets consumed_at on the token row IFF it is still unconsumed,
	// returning ErrInvalidVerificationToken when the row was already consumed
	// (atomic single-use guard — prevents a concurrent double-verify race).
	MarkConsumed(ctx context.Context, id uuid.UUID, now time.Time) error

	// InvalidateForUser marks all of a user's outstanding (unconsumed) tokens as
	// consumed so a resend supersedes prior tokens.
	InvalidateForUser(ctx context.Context, userID uuid.UUID, now time.Time) error
}

// CompanyStore defines DB operations for company records.
type CompanyStore interface {
	Create(ctx context.Context, c *domain.Company) error
	GetByID(ctx context.Context, id uuid.UUID) (*domain.Company, error)
}

// RefreshTokenStore defines DB operations for refresh token lifecycle.
type RefreshTokenStore interface {
	// Create inserts a new refresh token row.
	Create(ctx context.Context, rt *domain.RefreshToken) error

	// GetByID fetches a refresh token row by its PK.
	GetByID(ctx context.Context, id uuid.UUID) (*domain.RefreshToken, error)

	// MarkUsed atomically sets used_at and revoked_at on the row IFF used_at IS NULL
	// AND revoked_at IS NULL (CAS). Returns (true, nil) when the row was flipped —
	// caller should proceed to issue a new token pair. Returns (false, nil) when
	// either guard fails (row already used OR family already revoked) — caller MUST
	// treat this as a reuse/revoked attempt (RevokeFamily + ErrRefreshReuse). Any
	// DB error returns (false, err).
	MarkUsed(ctx context.Context, id uuid.UUID, now time.Time) (bool, error)

	// RevokeFamily sets revoked_at on all live rows in the family (reuse detection, logout).
	RevokeFamily(ctx context.Context, familyID uuid.UUID, now time.Time) error
}

// AuthIdentityStore defines DB operations for OAuth auth_identities records.
type AuthIdentityStore interface {
	// GetByProvider fetches an auth identity by provider + provider-side subject ID.
	// Returns domain.ErrNotFound when no matching row exists.
	GetByProvider(ctx context.Context, provider, providerSubject string) (*domain.AuthIdentity, error)

	// Create inserts a new auth_identities row.
	// Returns domain.ErrIdentityAlreadyBound on unique-constraint violation.
	Create(ctx context.Context, ai *domain.AuthIdentity) error

	// ListByUserID returns all auth identities linked to a given user.
	ListByUserID(ctx context.Context, userID uuid.UUID) ([]*domain.AuthIdentity, error)

	// DeleteByUserAndProvider removes a single identity row.
	// Returns domain.ErrNotFound when no matching row exists.
	DeleteByUserAndProvider(ctx context.Context, userID uuid.UUID, provider string) error
}

// PasswordResetTokenStore defines DB operations for single-use password-reset tokens.
// Only the SHA-256 hash of a token is ever stored.
type PasswordResetTokenStore interface {
	// Create inserts a new (hashed) password-reset token row.
	Create(ctx context.Context, t *domain.PasswordResetToken) error

	// GetByHash fetches a token row by its SHA-256 hash. Returns
	// ErrInvalidResetToken when no row matches (no oracle).
	GetByHash(ctx context.Context, tokenHash []byte) (*domain.PasswordResetToken, error)

	// MarkUsed atomically sets used_at on the token row IFF it is still unused
	// (used_at IS NULL). Returns ErrInvalidResetToken when the row was already used
	// (atomic single-use guard — prevents a concurrent double-reset race).
	MarkUsed(ctx context.Context, id uuid.UUID, now time.Time) error

	// InvalidateForUser marks all of a user's outstanding (unused) tokens as used
	// so a new forgot-password request supersedes prior tokens.
	InvalidateForUser(ctx context.Context, userID uuid.UUID, now time.Time) error
}

// IssueTokensInput groups the parameters needed to atomically create a new token pair.
type IssueTokensInput struct {
	UserID            uuid.UUID
	FamilyID          uuid.UUID
	PrevID            *uuid.UUID
	TokenHash         []byte
	DeviceFingerprint *string
	IPAddr            netip.Addr
	UserAgent         *string
	ExpiresAt         time.Time
}
