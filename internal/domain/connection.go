package domain

import (
	"time"

	"github.com/google/uuid"
)

// Connection represents a directed invite edge between two users that resolves
// into an undirected business connection once accepted (migration 000010).
// RequesterID is the user who sent the invite; AddresseeID is the recipient.
// Referential integrity is enforced in the service layer (no FK, red-line #9).
type Connection struct {
	ID          uuid.UUID `json:"id"`
	RequesterID uuid.UUID `json:"requesterId"`
	AddresseeID uuid.UUID `json:"addresseeId"`
	Status      string    `json:"status"`
	CreatedAt   time.Time `json:"createdAt"`
	UpdatedAt   time.Time `json:"updatedAt"`
}

// Connection status constants. These mirror the DB CHECK(status IN (...)) value
// allowlist on the connections table (a value check, NOT a foreign key).
const (
	ConnectionStatusPending  = "pending"
	ConnectionStatusAccepted = "accepted"
	ConnectionStatusDeclined = "declined"
)
