package domain

import (
	"time"

	"github.com/google/uuid"
)

// Company represents a registered company entity.
type Company struct {
	ID             uuid.UUID `json:"id"`
	Name           string    `json:"name"`
	RegistrationNo *string   `json:"registrationNo"`
	OwnerUserID    uuid.UUID `json:"ownerUserId"`
	Status         string    `json:"status"`
	CreatedAt      time.Time `json:"createdAt"`
	UpdatedAt      time.Time `json:"updatedAt"`
}

// CompanyStatus constants.
const (
	CompanyStatusActive    = "ACTIVE"
	CompanyStatusSuspended = "SUSPENDED"
)
