package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/CoverOnes/user/internal/domain"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// AuthIdentityStore implements store.AuthIdentityStore backed by Postgres.
type AuthIdentityStore struct {
	pool *pgxpool.Pool
}

// NewAuthIdentityStore returns a new AuthIdentityStore.
func NewAuthIdentityStore(pool *pgxpool.Pool) *AuthIdentityStore {
	return &AuthIdentityStore{pool: pool}
}

// GetByProvider fetches an auth identity by (provider, provider_subject).
// Returns domain.ErrNotFound when no matching row exists.
func (s *AuthIdentityStore) GetByProvider(ctx context.Context, provider, providerSubject string) (*domain.AuthIdentity, error) {
	q := `
	SELECT id, provider, provider_subject, user_id, email, linked_at
	FROM auth_identities
	WHERE provider = $1 AND provider_subject = $2
	`

	return scanAuthIdentity(s.pool.QueryRow(ctx, q, provider, providerSubject))
}

// Create inserts a new auth_identities row.
// Returns domain.ErrIdentityAlreadyBound on unique-constraint violation.
func (s *AuthIdentityStore) Create(ctx context.Context, ai *domain.AuthIdentity) error {
	q := `
	INSERT INTO auth_identities (id, provider, provider_subject, user_id, email, linked_at)
	VALUES ($1, $2, $3, $4, $5, $6)
	`

	_, err := s.pool.Exec(ctx, q, ai.ID, ai.Provider, ai.ProviderSubject, ai.UserID, ai.Email, ai.LinkedAt)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return domain.ErrIdentityAlreadyBound
		}

		return fmt.Errorf("insert auth_identity: %w", err)
	}

	return nil
}

// ListByUserID returns all auth identities linked to a given user.
func (s *AuthIdentityStore) ListByUserID(ctx context.Context, userID uuid.UUID) ([]*domain.AuthIdentity, error) {
	q := `
	SELECT id, provider, provider_subject, user_id, email, linked_at
	FROM auth_identities
	WHERE user_id = $1
	ORDER BY linked_at
	`

	rows, err := s.pool.Query(ctx, q, userID)
	if err != nil {
		return nil, fmt.Errorf("list auth_identities: %w", err)
	}

	defer rows.Close()

	var identities []*domain.AuthIdentity

	for rows.Next() {
		ai, scanErr := scanAuthIdentity(rows)
		if scanErr != nil {
			return nil, scanErr
		}

		identities = append(identities, ai)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list auth_identities rows: %w", err)
	}

	return identities, nil
}

// DeleteByUserAndProvider removes a single identity row.
// Returns domain.ErrNotFound when no matching row exists.
func (s *AuthIdentityStore) DeleteByUserAndProvider(ctx context.Context, userID uuid.UUID, provider string) error {
	q := `
	DELETE FROM auth_identities
	WHERE user_id = $1 AND provider = $2
	`

	tag, err := s.pool.Exec(ctx, q, userID, provider)
	if err != nil {
		return fmt.Errorf("delete auth_identity: %w", err)
	}

	if tag.RowsAffected() == 0 {
		return domain.ErrNotFound
	}

	return nil
}

func scanAuthIdentity(row pgx.Row) (*domain.AuthIdentity, error) {
	var ai domain.AuthIdentity

	err := row.Scan(&ai.ID, &ai.Provider, &ai.ProviderSubject, &ai.UserID, &ai.Email, &ai.LinkedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domain.ErrNotFound
		}

		return nil, fmt.Errorf("scan auth_identity: %w", err)
	}

	return &ai, nil
}
