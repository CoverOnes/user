package domain

import (
	"time"

	"github.com/google/uuid"
)

// SavedItem represents a single per-user bookmark over a heterogeneous target
// (migration 000012). ItemType is a VALUE-checked text ('job' | 'company'), NOT a
// foreign key: a saved 'job' is a marketplace Listing living in a DIFFERENT service's
// DB, so a FK would be impossible (red-line #9). Referential integrity is
// resolve-on-read in the service/handler layer (fetch the target; if it is gone, the
// row is simply not rendered).
type SavedItem struct {
	ID        uuid.UUID `json:"id"`
	UserID    uuid.UUID `json:"userId"`
	ItemType  string    `json:"itemType"`
	ItemID    uuid.UUID `json:"itemId"`
	CreatedAt time.Time `json:"createdAt"`
}

// SavedItem type constants. These mirror the DB CHECK(item_type IN (...)) value
// allowlist on the saved_items table (a value check, NOT a foreign key). 'user' and
// 'document' are reserved for future tabs and would widen the CHECK via a NEW
// migration (000012 is immutable once merged).
const (
	SavedItemTypeJob     = "job"
	SavedItemTypeCompany = "company"
)
