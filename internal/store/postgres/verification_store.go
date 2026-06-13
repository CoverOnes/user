//nolint:dupl // intentional mirror of password_reset_store.go — same lifecycle pattern, different domain type and SQL constants
package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/CoverOnes/user/internal/domain"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// SQL shared between the pool-backed and transactional verification stores so the
// column lists stay in lockstep.
const (
	verificationInsertSQL = `
		INSERT INTO email_verification_tokens
			(id, user_id, token_hash, expires_at, consumed_at, created_at)
		VALUES ($1, $2, $3, $4, $5, $6)`

	verificationSelectByHashSQL = `
		SELECT id, user_id, token_hash, expires_at, consumed_at, created_at
		FROM email_verification_tokens
		WHERE token_hash = $1`

	// MarkConsumed is atomic single-use: it only updates rows where consumed_at IS
	// NULL, so two concurrent verifications cannot both succeed.
	verificationMarkConsumedSQL = `
		UPDATE email_verification_tokens
		SET consumed_at = $2
		WHERE id = $1 AND consumed_at IS NULL`

	verificationInvalidateForUserSQL = `
		UPDATE email_verification_tokens
		SET consumed_at = $2
		WHERE user_id = $1 AND consumed_at IS NULL`
)

// VerificationStore implements store.EmailVerificationTokenStore over a pool.
type VerificationStore struct {
	pool *pgxpool.Pool
}

// NewVerificationStore returns a pool-backed VerificationStore.
func NewVerificationStore(pool *pgxpool.Pool) *VerificationStore {
	return &VerificationStore{pool: pool}
}

// Create inserts a new hashed verification token row.
func (s *VerificationStore) Create(ctx context.Context, t *domain.EmailVerificationToken) error {
	_, err := s.pool.Exec(ctx, verificationInsertSQL,
		t.ID, t.UserID, t.TokenHash, t.ExpiresAt, t.ConsumedAt, t.CreatedAt)
	if err != nil {
		return fmt.Errorf("insert verification token: %w", err)
	}

	return nil
}

// GetByHash fetches a token by its SHA-256 hash.
func (s *VerificationStore) GetByHash(ctx context.Context, tokenHash []byte) (*domain.EmailVerificationToken, error) {
	return scanVerificationToken(s.pool.QueryRow(ctx, verificationSelectByHashSQL, tokenHash))
}

// MarkConsumed atomically marks a single token consumed (single-use guard).
func (s *VerificationStore) MarkConsumed(ctx context.Context, id uuid.UUID, now time.Time) error {
	tag, err := s.pool.Exec(ctx, verificationMarkConsumedSQL, id, now)
	if err != nil {
		return fmt.Errorf("mark verification token consumed: %w", err)
	}

	if tag.RowsAffected() == 0 {
		// Already consumed (or vanished) → same generic error, no oracle.
		return domain.ErrInvalidVerificationToken
	}

	return nil
}

// InvalidateForUser consumes all of a user's outstanding tokens.
func (s *VerificationStore) InvalidateForUser(ctx context.Context, userID uuid.UUID, now time.Time) error {
	_, err := s.pool.Exec(ctx, verificationInvalidateForUserSQL, userID, now)
	if err != nil {
		return fmt.Errorf("invalidate verification tokens for user: %w", err)
	}

	return nil
}

// txVerificationStore is the transactional variant used inside WithTx.
type txVerificationStore struct {
	tx txExecer
}

func (s *txVerificationStore) Create(ctx context.Context, t *domain.EmailVerificationToken) error {
	_, err := s.tx.Exec(ctx, verificationInsertSQL,
		t.ID, t.UserID, t.TokenHash, t.ExpiresAt, t.ConsumedAt, t.CreatedAt)
	if err != nil {
		return fmt.Errorf("insert verification token (tx): %w", err)
	}

	return nil
}

func (s *txVerificationStore) GetByHash(ctx context.Context, tokenHash []byte) (*domain.EmailVerificationToken, error) {
	return scanVerificationToken(s.tx.QueryRow(ctx, verificationSelectByHashSQL, tokenHash))
}

func (s *txVerificationStore) MarkConsumed(ctx context.Context, id uuid.UUID, now time.Time) error {
	tag, err := s.tx.Exec(ctx, verificationMarkConsumedSQL, id, now)
	if err != nil {
		return fmt.Errorf("mark verification token consumed (tx): %w", err)
	}

	if tag.RowsAffected() == 0 {
		return domain.ErrInvalidVerificationToken
	}

	return nil
}

func (s *txVerificationStore) InvalidateForUser(ctx context.Context, userID uuid.UUID, now time.Time) error {
	_, err := s.tx.Exec(ctx, verificationInvalidateForUserSQL, userID, now)
	if err != nil {
		return fmt.Errorf("invalidate verification tokens for user (tx): %w", err)
	}

	return nil
}

func scanVerificationToken(row pgx.Row) (*domain.EmailVerificationToken, error) {
	var t domain.EmailVerificationToken

	err := row.Scan(&t.ID, &t.UserID, &t.TokenHash, &t.ExpiresAt, &t.ConsumedAt, &t.CreatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// Not-found → same generic error as expired/consumed (no oracle).
			return nil, domain.ErrInvalidVerificationToken
		}

		return nil, fmt.Errorf("scan verification token: %w", err)
	}

	return &t, nil
}
