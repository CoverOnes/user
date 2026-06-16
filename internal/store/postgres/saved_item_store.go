package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/CoverOnes/user/internal/domain"
	"github.com/CoverOnes/user/internal/store"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// savedItemUserItemUniqIndex is the name of the unique index that enforces "at most
// one live bookmark per (user, item_type, item_id)" (migration 000012). A 23505
// carrying this constraint name is mapped to domain.ErrSavedItemExists; any other
// 23505 is surfaced as a wrapped error so an unrelated future unique constraint is
// never misreported.
const savedItemUserItemUniqIndex = "saved_items_user_item_uniq"

// savedCompanyColumns is the EXPLICIT PII-safe projection of a saved 'company' card.
// It lists ONLY non-PII public company columns (mirrors the public CompanyProfile
// allowlist). HIGH-sensitivity / internal columns (registration_no, owner_user_id,
// status) are deliberately excluded so a saved-companies list can never leak them.
// `s` is the saved_items row; `c` is the joined companies row. The column order MUST
// stay in lockstep with scanSavedCompany below.
const savedCompanyColumns = `
	s.id, s.created_at,
	c.id, c.handle, c.name, c.tagline, c.location, c.industry, c.company_size, c.logo_url`

// SavedItemStore implements store.SavedItemStore backed by Postgres.
type SavedItemStore struct {
	pool *pgxpool.Pool
}

// NewSavedItemStore returns a new SavedItemStore.
func NewSavedItemStore(pool *pgxpool.Pool) *SavedItemStore {
	return &SavedItemStore{pool: pool}
}

// Create inserts a new bookmark. A live bookmark already covering the
// (user_id, item_type, item_id) triple violates saved_items_user_item_uniq (23505)
// → ErrSavedItemExists. The unique index is the race-safe authority — we NEVER
// pre-check then insert (TOCTOU-safe).
func (s *SavedItemStore) Create(ctx context.Context, si *domain.SavedItem) error {
	q := `
	INSERT INTO saved_items (id, user_id, item_type, item_id, created_at)
	VALUES ($1, $2, $3, $4, $5)
	`

	_, err := s.pool.Exec(ctx, q, si.ID, si.UserID, si.ItemType, si.ItemID, si.CreatedAt)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" && pgErr.ConstraintName == savedItemUserItemUniqIndex {
			return domain.ErrSavedItemExists
		}

		return fmt.Errorf("insert saved item: %w", err)
	}

	return nil
}

// DeleteByUserAndItem hard-deletes the caller's bookmark identified by
// (userID, itemType, itemID). The WHERE clause is identity-scoped (user_id = caller),
// so a caller can only ever delete their OWN bookmark. It is IDEMPOTENT: an absent
// bookmark yields (false, nil) — toggle UX must not error on a double-unsave race.
func (s *SavedItemStore) DeleteByUserAndItem(ctx context.Context, userID uuid.UUID, itemType string, itemID uuid.UUID) (bool, error) {
	q := `DELETE FROM saved_items WHERE user_id = $1 AND item_type = $2 AND item_id = $3`

	tag, err := s.pool.Exec(ctx, q, userID, itemType, itemID)
	if err != nil {
		return false, fmt.Errorf("delete saved item: %w", err)
	}

	return tag.RowsAffected() > 0, nil
}

// ListJobRefs returns the caller's saved 'job' bookmarks as bare references (no
// cross-call to the delegated marketplace), ordered newest-saved-first. The index
// saved_items_user_type_created_idx backs this hot path.
func (s *SavedItemStore) ListJobRefs(ctx context.Context, userID uuid.UUID) ([]domain.SavedItem, error) {
	q := `
	SELECT id, user_id, item_type, item_id, created_at
	FROM saved_items
	WHERE user_id = $1 AND item_type = 'job'
	ORDER BY created_at DESC
	`

	rows, err := s.pool.Query(ctx, q, userID)
	if err != nil {
		return nil, fmt.Errorf("query saved job refs: %w", err)
	}

	defer rows.Close()

	var out []domain.SavedItem

	for rows.Next() {
		var si domain.SavedItem
		if scanErr := rows.Scan(&si.ID, &si.UserID, &si.ItemType, &si.ItemID, &si.CreatedAt); scanErr != nil {
			return nil, fmt.Errorf("scan saved job ref: %w", scanErr)
		}

		out = append(out, si)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate saved job refs: %w", err)
	}

	return out, nil
}

// scanSavedCompany scans the savedCompanyColumns projection into a
// store.SavedCompanyRow. The column order MUST stay in lockstep with
// savedCompanyColumns.
func scanSavedCompany(row pgx.Row) (store.SavedCompanyRow, error) {
	var r store.SavedCompanyRow

	err := row.Scan(
		&r.SavedID, &r.SavedAt,
		&r.CompanyID, &r.Handle, &r.Name, &r.Tagline, &r.Location, &r.Industry, &r.CompanySize, &r.LogoURL,
	)
	if err != nil {
		return store.SavedCompanyRow{}, fmt.Errorf("scan saved company: %w", err)
	}

	return r, nil
}

// ListCompaniesForUser returns the caller's saved 'company' bookmarks JOINed to the
// in-service companies table, projecting the PII-safe company card, newest first. The
// INNER JOIN is the resolve-on-read mechanism: a saved company whose row is gone
// simply does not JOIN and is dropped from the list (no fabricated placeholder, no FK).
func (s *SavedItemStore) ListCompaniesForUser(ctx context.Context, userID uuid.UUID) ([]store.SavedCompanyRow, error) {
	q := `
	SELECT ` + savedCompanyColumns + `
	FROM saved_items s
	JOIN companies c ON c.id = s.item_id
	WHERE s.user_id = $1 AND s.item_type = 'company'
	ORDER BY s.created_at DESC
	`

	rows, err := s.pool.Query(ctx, q, userID)
	if err != nil {
		return nil, fmt.Errorf("query saved companies: %w", err)
	}

	defer rows.Close()

	var out []store.SavedCompanyRow

	for rows.Next() {
		r, scanErr := scanSavedCompany(rows)
		if scanErr != nil {
			return nil, scanErr
		}

		out = append(out, r)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate saved companies: %w", err)
	}

	return out, nil
}
