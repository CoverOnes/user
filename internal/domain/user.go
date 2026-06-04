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
	PasswordHash string     `json:"-"`
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
	LegalNameEnc  []byte     `json:"-"`
	NationalIDEnc []byte     `json:"-"`
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
