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

	// SetEmailVerified sets users.email_verified = true for the given user.
	// Idempotent; returns ErrNotFound if no live row matches.
	SetEmailVerified(ctx context.Context, id uuid.UUID) error
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

	// MarkUsed sets used_at and revoked_at on the row (rotation supersede).
	MarkUsed(ctx context.Context, id uuid.UUID, now time.Time) error

	// RevokeFamily sets revoked_at on all live rows in the family (reuse detection, logout).
	RevokeFamily(ctx context.Context, familyID uuid.UUID, now time.Time) error
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
