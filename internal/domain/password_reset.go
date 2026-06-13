package domain

import (
	"time"

	"github.com/google/uuid"
)

// PasswordResetToken is a single-use, short-lived token that allows a user to set
// a new password. Only the SHA-256 hash of the raw token is stored (TokenHash);
// the raw value is delivered by email and never persisted.
type PasswordResetToken struct {
	ID        uuid.UUID  `json:"id"`
	UserID    uuid.UUID  `json:"userId"`
	TokenHash []byte     `json:"-"`
	ExpiresAt time.Time  `json:"expiresAt"`
	UsedAt    *time.Time `json:"usedAt"`
	CreatedAt time.Time  `json:"createdAt"`
}
