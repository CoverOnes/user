// Package domain defines the core domain types for the user service.
package domain

import (
	"net/netip"
	"time"

	"github.com/google/uuid"
)

// User represents a registered user account.
type User struct {
	ID           uuid.UUID  `json:"id"`
	Email        string     `json:"email"`
	PasswordHash *string    `json:"-"` // NULL for OAuth-only accounts (migration 000007)
	DisplayName  string     `json:"displayName"`
	AvatarURL    *string    `json:"avatarUrl"`
	AccountType  string     `json:"accountType"`
	KYCTier      int16      `json:"kycTier"`
	CompanyID    *uuid.UUID `json:"companyId"`
	Status       string     `json:"status"`
	// EmailVerified reflects users.email_verified — whether the account has
	// completed email verification. Lifted by POST /v1/auth/verify-email.
	EmailVerified bool `json:"emailVerified"`
	// LegalNameEnc / NationalIDEnc hold AES-256-GCM ciphertext of the user's
	// HIGH-sensitivity PII. They are JSON-excluded so the plaintext (and even the
	// ciphertext) never serializes into an API response. NationalIDEnc is nil for
	// COMPANY accounts.
	LegalNameEnc  []byte `json:"-"`
	NationalIDEnc []byte `json:"-"`
	// MFAEnabled reports whether TOTP 2FA has been confirmed-and-enabled (Inc3).
	// false while a TOTP secret is merely pending (enrolled but not confirmed).
	// Login does NOT consult this flag in Increment 3 — enforcement is deferred.
	MFAEnabled bool `json:"mfaEnabled"`
	// TOTPSecretEnc is the AES-256-GCM ciphertext of the user's base32 TOTP secret.
	// It is written (PENDING) at enroll and verified at confirm/verify; the plaintext
	// secret is returned to the client ONCE at enroll (for the QR / manual entry) and
	// NEVER again. JSON-excluded so the ciphertext never serializes into a response.
	TOTPSecretEnc []byte `json:"-"`
	// MFABackupCodesEnc is the AES-256-GCM ciphertext of a JSON array of SHA-256
	// hashes of the user's one-time backup codes. The raw codes are returned ONCE at
	// confirm and never persisted in the clear. JSON-excluded.
	MFABackupCodesEnc []byte `json:"-"`
	// MFAEnrolledAt is when MFA was confirmed-and-enabled (set at confirm, cleared at
	// disable). nil while MFA is not enabled.
	MFAEnrolledAt *time.Time `json:"mfaEnrolledAt,omitempty"`
	TokenVersion  int        `json:"-"`
	DeletedAt     *time.Time `json:"deletedAt,omitempty"`
	CreatedAt     time.Time  `json:"createdAt"`
	UpdatedAt     time.Time  `json:"updatedAt"`
}

// AccountType constants.
const (
	AccountTypePersonal = "PERSONAL"
	AccountTypeCompany  = "COMPANY"
)

// UserStatus constants.
const (
	UserStatusActive              = "ACTIVE"
	UserStatusSuspended           = "SUSPENDED"
	UserStatusPendingVerification = "PENDING_VERIFICATION"
)

// ValidAccountTypes is the allowlist for account types.
var ValidAccountTypes = map[string]bool{
	AccountTypePersonal: true,
	AccountTypeCompany:  true,
}

// ValidUserStatuses is the allowlist for user statuses.
var ValidUserStatuses = map[string]bool{
	UserStatusActive:              true,
	UserStatusSuspended:           true,
	UserStatusPendingVerification: true,
}

// AuthIdentity represents a linked OAuth provider account for a user.
// One user may have at most one identity per provider,
// enforced by UNIQUE(provider, provider_subject) in the DB.
type AuthIdentity struct {
	ID              uuid.UUID `json:"id"`
	Provider        string    `json:"provider"`
	ProviderSubject string    `json:"-"` // provider-side subject — never exposed to clients
	UserID          uuid.UUID `json:"userId"`
	Email           *string   `json:"email,omitempty"`
	LinkedAt        time.Time `json:"linkedAt"`
}

// OAuthProvider constants.
const (
	OAuthProviderGoogle = "google"
	OAuthProviderLINE   = "line"
)

// ValidOAuthProviders is the allowlist for OAuth providers.
var ValidOAuthProviders = map[string]bool{
	OAuthProviderGoogle: true,
	OAuthProviderLINE:   true,
}

// RefreshToken represents a stored refresh token record.
type RefreshToken struct {
	ID                uuid.UUID  `json:"id"`
	UserID            uuid.UUID  `json:"userId"`
	FamilyID          uuid.UUID  `json:"familyId"`
	TokenHash         []byte     `json:"-"`
	PrevID            *uuid.UUID `json:"prevId"`
	UsedAt            *time.Time `json:"usedAt"`
	RevokedAt         *time.Time `json:"revokedAt"`
	DeviceFingerprint *string    `json:"deviceFingerprint"`
	IPAddr            netip.Addr `json:"ipAddr"`
	UserAgent         *string    `json:"userAgent"`
	ExpiresAt         time.Time  `json:"expiresAt"`
	CreatedAt         time.Time  `json:"createdAt"`
	// TokenVersion records the user's token_version at the time this refresh token
	// was issued. Compared server-side at refresh against the fresh DB value so that
	// a logout-all (token_version bump) is enforced without storing version state
	// on the client (M1 — server-side enforcement).
	TokenVersion int `json:"-"`
}
