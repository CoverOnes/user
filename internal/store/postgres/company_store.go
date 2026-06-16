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

// companyHandleUniqueIndex is the name of the partial-unique index that enforces
// case-insensitive handle uniqueness over companies with a non-null handle
// (migration 000011). A 23505 carrying this constraint name maps to
// domain.ErrHandleTaken; any other 23505 is surfaced as a wrapped error so an
// unrelated future unique constraint is never misreported.
const companyHandleUniqueIndex = "companies_handle_unique"

// updateCompanySQL is the full-replace UPDATE for the editable company profile
// fields, bumping updated_at. registration_no is NOT touched (set at register time,
// not client-editable). RowsAffected()==0 means no row matched → ErrCompanyNotFound.
const updateCompanySQL = `
	UPDATE companies SET
		name         = $2,
		handle       = $3,
		tagline      = $4,
		about        = $5,
		location     = $6,
		website      = $7,
		industry     = $8,
		company_size = $9,
		founded_year = $10,
		logo_url     = $11,
		cover_url    = $12,
		updated_at   = now()
	WHERE id = $1`

// companySelectColumns is the shared SELECT column list consumed by scanCompany.
// The trailing public-profile columns (handle..cover_url) were added in 000011;
// they MUST stay in lockstep with scanCompany's Scan call below. Shared by both the
// pool-backed CompanyStore and the tx-backed txCompanyStore (no dupl).
const companySelectColumns = `
	id, name, registration_no, owner_user_id, status, created_at, updated_at,
	handle, tagline, about, location, website,
	industry, company_size, founded_year, logo_url, cover_url`

// companyMemberColumns is the EXPLICIT PII-safe projection of a company team-roster
// entry. It lists ONLY non-PII display columns (mirrors the public-profile /
// connection-card allowlist). PII columns (email, national_id_enc, legal_name_enc,
// kyc_tier, status, …) are deliberately excluded so a members list can never leak
// them. The `u` alias is the member user row; `$1` is the company id used to derive
// is_owner against companies.owner_user_id. Soft-deleted members are filtered out.
const companyMemberColumns = `
	u.id, u.display_name, u.handle, u.headline, u.avatar_url,
	(u.id = co.owner_user_id) AS is_owner`

// listMembersSQL returns the live team roster for a company id, ordered by
// created_at ASC (resolved-decision #3). The companies row is joined ONLY to derive
// is_owner; a LEFT JOIN is intentional so the query still returns members even in
// the (impossible-in-practice) case the company row is missing.
const listMembersSQL = `
	SELECT ` + companyMemberColumns + `
	FROM users u
	LEFT JOIN companies co ON co.id = $1
	WHERE u.company_id = $1
	  AND u.deleted_at IS NULL
	ORDER BY u.created_at ASC`

// CompanyStore implements store.CompanyStore backed by Postgres.
type CompanyStore struct {
	pool *pgxpool.Pool
}

// NewCompanyStore returns a new CompanyStore.
func NewCompanyStore(pool *pgxpool.Pool) *CompanyStore {
	return &CompanyStore{pool: pool}
}

// Create inserts a new company row.
func (s *CompanyStore) Create(ctx context.Context, c *domain.Company) error {
	q := `
	INSERT INTO companies
		(id, name, registration_no, owner_user_id, status, created_at, updated_at)
	VALUES ($1, $2, $3, $4, $5, $6, $7)
	`

	_, err := s.pool.Exec(
		ctx, q,
		c.ID, c.Name, c.RegistrationNo, c.OwnerUserID,
		c.Status, c.CreatedAt, c.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("insert company: %w", err)
	}

	return nil
}

// scanCompany scans the companySelectColumns projection into a *domain.Company. The
// column order MUST stay in lockstep with companySelectColumns. pgx.ErrNoRows maps to
// domain.ErrNotFound (the service layer normalizes that to ErrCompanyNotFound for the
// company endpoints). Shared by the pool + tx GetByID (no dupl).
func scanCompany(row pgx.Row) (*domain.Company, error) {
	var c domain.Company

	err := row.Scan(
		&c.ID, &c.Name, &c.RegistrationNo, &c.OwnerUserID,
		&c.Status, &c.CreatedAt, &c.UpdatedAt,
		&c.Handle, &c.Tagline, &c.About, &c.Location, &c.Website,
		&c.Industry, &c.CompanySize, &c.FoundedYear, &c.LogoURL, &c.CoverURL,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domain.ErrNotFound
		}

		return nil, fmt.Errorf("scan company: %w", err)
	}

	return &c, nil
}

// scanCompanyMembers drains a rows result of companyMemberColumns into the PII-safe
// carrier slice. Shared by the pool + tx ListMembers (no dupl). The caller owns
// closing rows; this helper only iterates + scans.
func scanCompanyMembers(rows pgx.Rows) ([]store.CompanyMember, error) {
	var out []store.CompanyMember

	for rows.Next() {
		var m store.CompanyMember
		if scanErr := rows.Scan(
			&m.UserID, &m.DisplayName, &m.Handle, &m.Headline, &m.AvatarURL, &m.IsOwner,
		); scanErr != nil {
			return nil, fmt.Errorf("scan company member: %w", scanErr)
		}

		out = append(out, m)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate company members: %w", err)
	}

	return out, nil
}

// GetByID fetches a company by PK, including the 000011 public-profile columns.
func (s *CompanyStore) GetByID(ctx context.Context, id uuid.UUID) (*domain.Company, error) {
	q := `SELECT ` + companySelectColumns + ` FROM companies WHERE id = $1`

	return scanCompany(s.pool.QueryRow(ctx, q, id))
}

// isCompanyHandleTaken reports whether err is a Postgres 23505 unique-violation on
// companies_handle_unique specifically. Any other 23505 (a future unrelated unique
// constraint) is NOT misreported as ErrHandleTaken.
func isCompanyHandleTaken(err error) bool {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		return pgErr.ConstraintName == companyHandleUniqueIndex
	}

	return false
}

// Update replaces the editable public-profile fields for the company id, bumping
// updated_at. A 23505 on companies_handle_unique maps to domain.ErrHandleTaken (the
// partial-unique index is the race-safe authority — we never pre-check then write).
// RowsAffected()==0 means no row matched the id → domain.ErrCompanyNotFound. The
// carrier is taken by pointer (gocritic hugeParam: CompanyUpdate is >80 bytes).
func (s *CompanyStore) Update(ctx context.Context, id uuid.UUID, in *store.CompanyUpdate) error {
	tag, err := s.pool.Exec(
		ctx, updateCompanySQL,
		id, in.Name, in.Handle, in.Tagline, in.About, in.Location,
		in.Website, in.Industry, in.CompanySize, in.FoundedYear, in.LogoURL, in.CoverURL,
	)
	if err != nil {
		if isCompanyHandleTaken(err) {
			return domain.ErrHandleTaken
		}

		return fmt.Errorf("update company: %w", err)
	}

	if tag.RowsAffected() == 0 {
		return domain.ErrCompanyNotFound
	}

	return nil
}

// ListMembers returns the company's team roster (live users WHERE company_id = id),
// ordered created_at ASC, projecting the PII-safe columns with IsOwner derived from
// companies.owner_user_id. An unknown company id (or a company with no members)
// returns an empty slice with no error.
func (s *CompanyStore) ListMembers(ctx context.Context, companyID uuid.UUID) ([]store.CompanyMember, error) {
	rows, err := s.pool.Query(ctx, listMembersSQL, companyID)
	if err != nil {
		return nil, fmt.Errorf("query company members: %w", err)
	}

	defer rows.Close()

	return scanCompanyMembers(rows)
}
