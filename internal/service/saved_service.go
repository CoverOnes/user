package service

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/CoverOnes/user/internal/domain"
	"github.com/CoverOnes/user/internal/store"
	"github.com/google/uuid"
)

// SavedService holds the business logic for the P4 Saved bookmarks aggregate. It
// validates referential integrity in code (no FK, red-line #9): saving a company
// confirms the company row exists in-service before inserting a bookmark; saving a
// job is NOT existence-checked (the target is a marketplace Listing in a DELEGATED
// service DB the user service never cross-calls — a stale id resolves to nothing on
// read and is skipped).
type SavedService struct {
	companies store.CompanyStore
	saved     store.SavedItemStore
}

// NewSavedService creates a SavedService.
func NewSavedService(companies store.CompanyStore, saved store.SavedItemStore) *SavedService {
	return &SavedService{companies: companies, saved: saved}
}

// maxSavedPerUserPerType is the hard ceiling on how many bookmarks a single user may
// hold for one item_type. It is an application-layer guard against unbounded growth of
// the shared saved_items table (OWASP API4): an authenticated client can script
// POST /v1/me/saved with random job item_ids (job targets are never existence-checked,
// they live in the delegated marketplace DB), so without a per-user ceiling the table
// can be grown without limit. This guard is INDEPENDENT of the request rate limiter —
// it cannot be disabled by config (e.g. USER_USER_RATE_LIMIT_PER_MIN=0) — so it holds
// even when the rate limiter is off.
const maxSavedPerUserPerType = 1000

// validItemType reports whether t is an accepted bookmark item_type. It mirrors the
// DB CHECK(item_type IN (...)) value allowlist (a value check, NOT a foreign key);
// the service rejects an unknown type BEFORE any DB hit so the caller gets a precise
// 400 rather than a raw constraint violation (platform §5.2: validate client-side).
func validItemType(t string) bool {
	return t == domain.SavedItemTypeJob || t == domain.SavedItemTypeCompany
}

// Save creates a bookmark for callerID over (itemType, itemID).
//
// Order of checks:
//  1. itemType must be in the value allowlist → ErrValidation (400) — cheap, no DB hit.
//  2. referential integrity in code (no FK): company targets are verified via
//     companies.GetByID (absent → ErrSavedTargetNotFound, 404); job targets are NOT
//     checked (the delegated marketplace DB is unreachable from this service; a stale
//     id resolves to nothing on read and is skipped — no fake data, no FK).
//  3. per-user-per-type ceiling: CountByUserAndType must be < maxSavedPerUserPerType,
//     else ErrValidation (400) — the OWASP API4 unbounded-growth guard, independent of
//     the rate limiter (config cannot disable it).
//  4. saved.Create — the unique index is the race-safe authority for the
//     "already saved" case (→ ErrSavedItemExists / 409); we never check-then-insert.
//
// Returns the created bookmark on success.
func (s *SavedService) Save(ctx context.Context, callerID uuid.UUID, itemType string, itemID uuid.UUID) (*domain.SavedItem, error) {
	if !validItemType(itemType) {
		return nil, fmt.Errorf("%w: itemType must be 'job' or 'company'", domain.ErrValidation)
	}

	// Referential-integrity-in-code: only the company target is verified (it lives in
	// this service's DB). GetByID returns ErrNotFound for an absent row → mapped to
	// the saved-specific ErrSavedTargetNotFound (404).
	if itemType == domain.SavedItemTypeCompany {
		if _, err := s.companies.GetByID(ctx, itemID); err != nil {
			if errors.Is(err, domain.ErrNotFound) {
				return nil, domain.ErrSavedTargetNotFound
			}

			return nil, fmt.Errorf("lookup saved company target: %w", err)
		}
	}

	// Unbounded-growth guard (OWASP API4): cap the number of bookmarks a single user
	// may hold per item_type. This is intentionally enforced here in the service — NOT
	// at the rate limiter — so it cannot be disabled by config and holds even when the
	// per-user rate limiter is off.
	n, err := s.saved.CountByUserAndType(ctx, callerID, itemType)
	if err != nil {
		return nil, fmt.Errorf("count saved items for cap check: %w", err)
	}

	if n >= maxSavedPerUserPerType {
		return nil, fmt.Errorf("%w: saved limit reached (max %d %s items)", domain.ErrValidation, maxSavedPerUserPerType, itemType)
	}

	si := &domain.SavedItem{
		ID:        uuid.New(),
		UserID:    callerID,
		ItemType:  itemType,
		ItemID:    itemID,
		CreatedAt: time.Now().UTC(),
	}

	if err := s.saved.Create(ctx, si); err != nil {
		// ErrSavedItemExists (dup 23505) is surfaced as-is → 409.
		return nil, err
	}

	return si, nil
}

// Unsave hard-deletes the caller's bookmark over (itemType, itemID). It is idempotent:
// an absent bookmark returns (false, nil) — toggle UX must survive a double-unsave
// race (resolved-decision #2). The itemType is validated first so an unknown type is
// a precise 400 rather than a silent no-op.
func (s *SavedService) Unsave(ctx context.Context, callerID uuid.UUID, itemType string, itemID uuid.UUID) (bool, error) {
	if !validItemType(itemType) {
		return false, fmt.Errorf("%w: itemType must be 'job' or 'company'", domain.ErrValidation)
	}

	return s.saved.DeleteByUserAndItem(ctx, callerID, itemType, itemID)
}

// ListJobs returns the caller's saved 'job' bookmarks as bare references (the FE
// hydrates each via the delegated marketplace getListing), newest-saved-first.
func (s *SavedService) ListJobs(ctx context.Context, callerID uuid.UUID) ([]domain.SavedItem, error) {
	return s.saved.ListJobRefs(ctx, callerID)
}

// ListCompanies returns the caller's saved 'company' bookmarks JOINed in-service to
// the PII-safe company card, newest first. A saved company whose row is gone is
// skipped by the JOIN (resolve-on-read).
func (s *SavedService) ListCompanies(ctx context.Context, callerID uuid.UUID) ([]store.SavedCompanyRow, error) {
	return s.saved.ListCompaniesForUser(ctx, callerID)
}
