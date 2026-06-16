package domain

import (
	"time"

	"github.com/google/uuid"
)

// Company represents a registered company entity. The public-profile columns
// (migration 000011) are all nullable and non-PII. RegistrationNo (from 000002)
// is HIGH-sensitivity owner-only data: it is JSON-tagged here for completeness but
// the handlers build EXPLICIT projections, so it is surfaced ONLY in the owner view
// (/v1/me/company) and NEVER in a public response (see handler.companyPublic /
// companyMember).
type Company struct {
	ID             uuid.UUID `json:"id"`
	Name           string    `json:"name"`
	RegistrationNo *string   `json:"registrationNo"`
	OwnerUserID    uuid.UUID `json:"ownerUserId"`
	Status         string    `json:"status"`

	// Public-profile display fields (migration 000011). All nullable, non-PII.
	// Handle is the case-insensitive public company username (citext), unique among
	// companies with a non-null handle.
	Handle      *string `json:"handle"`
	Tagline     *string `json:"tagline"`
	About       *string `json:"about"`
	Location    *string `json:"location"`
	Website     *string `json:"website"`
	Industry    *string `json:"industry"`
	CompanySize *string `json:"companySize"`
	FoundedYear *int16  `json:"foundedYear"`
	LogoURL     *string `json:"logoUrl"`
	CoverURL    *string `json:"coverUrl"`

	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}

// CompanyStatus constants.
const (
	CompanyStatusActive    = "ACTIVE"
	CompanyStatusSuspended = "SUSPENDED"
)
