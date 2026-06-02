package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/CoverOnes/user/internal/domain"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

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

	_, err := s.pool.Exec(ctx, q,
		c.ID, c.Name, c.RegistrationNo, c.OwnerUserID,
		c.Status, c.CreatedAt, c.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("insert company: %w", err)
	}

	return nil
}

// GetByID fetches a company by PK.
func (s *CompanyStore) GetByID(ctx context.Context, id uuid.UUID) (*domain.Company, error) {
	q := `
	SELECT id, name, registration_no, owner_user_id, status, created_at, updated_at
	FROM companies
	WHERE id = $1
	`

	var c domain.Company
	err := s.pool.QueryRow(ctx, q, id).Scan(
		&c.ID, &c.Name, &c.RegistrationNo, &c.OwnerUserID,
		&c.Status, &c.CreatedAt, &c.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domain.ErrNotFound
		}

		return nil, fmt.Errorf("scan company: %w", err)
	}

	return &c, nil
}
