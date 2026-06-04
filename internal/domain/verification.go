package domain

import (
	"time"

	"github.com/google/uuid"
)

// EmailVerificationToken is a single-use, short-lived token that proves the user
// controls their email address. Only the SHA-256 hash of the raw token is stored
// (TokenHash); the raw value is delivered by email and never persisted.
type EmailVerificationToken struct {
	ID         uuid.UUID  `json:"id"`
	UserID     uuid.UUID  `json:"userId"`
	TokenHash  []byte     `json:"-"`
	ExpiresAt  time.Time  `json:"expiresAt"`
	ConsumedAt *time.Time `json:"consumedAt"`
	CreatedAt  time.Time  `json:"createdAt"`
}
