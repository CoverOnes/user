//nolint:dupl // intentional mirror of verification_store.go — same lifecycle pattern, different domain type and SQL constants
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

// SQL shared between the pool-backed and transactional password-reset stores so the
// column lists stay in lockstep.
const (
	resetInsertSQL = `
		INSERT INTO password_reset_tokens
			(id, user_id, token_hash, expires_at, used_at, created_at)
		VALUES ($1, $2, $3, $4, $5, $6)`

	resetSelectByHashSQL = `
		SELECT id, user_id, token_hash, expires_at, used_at, created_at
		FROM password_reset_tokens
		WHERE token_hash = $1`

	// resetMarkUsedSQL is atomic single-use: it only updates rows where used_at IS
	// NULL, so two concurrent resets cannot both succeed.
	resetMarkUsedSQL = `
		UPDATE password_reset_tokens
		SET used_at = $2
		WHERE id = $1 AND used_at IS NULL`

	resetInvalidateForUserSQL = `
		UPDATE password_reset_tokens
		SET used_at = $2
		WHERE user_id = $1 AND used_at IS NULL`
)

// PasswordResetStore implements store.PasswordResetTokenStore over a pool.
type PasswordResetStore struct {
	pool *pgxpool.Pool
}

// NewPasswordResetStore returns a pool-backed PasswordResetStore.
func NewPasswordResetStore(pool *pgxpool.Pool) *PasswordResetStore {
	return &PasswordResetStore{pool: pool}
}

// Create inserts a new hashed password-reset token row.
func (s *PasswordResetStore) Create(ctx context.Context, t *domain.PasswordResetToken) error {
	_, err := s.pool.Exec(ctx, resetInsertSQL,
		t.ID, t.UserID, t.TokenHash, t.ExpiresAt, t.UsedAt, t.CreatedAt)
	if err != nil {
		return fmt.Errorf("insert password reset token: %w", err)
	}

	return nil
}

// GetByHash fetches a token by its SHA-256 hash.
func (s *PasswordResetStore) GetByHash(ctx context.Context, tokenHash []byte) (*domain.PasswordResetToken, error) {
	return scanResetToken(s.pool.QueryRow(ctx, resetSelectByHashSQL, tokenHash))
}

// MarkUsed atomically marks a single token used (single-use guard).
func (s *PasswordResetStore) MarkUsed(ctx context.Context, id uuid.UUID, now time.Time) error {
	tag, err := s.pool.Exec(ctx, resetMarkUsedSQL, id, now)
	if err != nil {
		return fmt.Errorf("mark password reset token used: %w", err)
	}

	if tag.RowsAffected() == 0 {
		// Already used (or vanished) → same generic error, no oracle.
		return domain.ErrInvalidResetToken
	}

	return nil
}

// InvalidateForUser marks all of a user's outstanding tokens as used.
func (s *PasswordResetStore) InvalidateForUser(ctx context.Context, userID uuid.UUID, now time.Time) error {
	_, err := s.pool.Exec(ctx, resetInvalidateForUserSQL, userID, now)
	if err != nil {
		return fmt.Errorf("invalidate password reset tokens for user: %w", err)
	}

	return nil
}

// txPasswordResetStore is the transactional variant used inside WithResetTx.
type txPasswordResetStore struct {
	tx txExecer
}

func (s *txPasswordResetStore) Create(ctx context.Context, t *domain.PasswordResetToken) error {
	_, err := s.tx.Exec(ctx, resetInsertSQL,
		t.ID, t.UserID, t.TokenHash, t.ExpiresAt, t.UsedAt, t.CreatedAt)
	if err != nil {
		return fmt.Errorf("insert password reset token (tx): %w", err)
	}

	return nil
}

func (s *txPasswordResetStore) GetByHash(ctx context.Context, tokenHash []byte) (*domain.PasswordResetToken, error) {
	return scanResetToken(s.tx.QueryRow(ctx, resetSelectByHashSQL, tokenHash))
}

func (s *txPasswordResetStore) MarkUsed(ctx context.Context, id uuid.UUID, now time.Time) error {
	tag, err := s.tx.Exec(ctx, resetMarkUsedSQL, id, now)
	if err != nil {
		return fmt.Errorf("mark password reset token used (tx): %w", err)
	}

	if tag.RowsAffected() == 0 {
		return domain.ErrInvalidResetToken
	}

	return nil
}

func (s *txPasswordResetStore) InvalidateForUser(ctx context.Context, userID uuid.UUID, now time.Time) error {
	_, err := s.tx.Exec(ctx, resetInvalidateForUserSQL, userID, now)
	if err != nil {
		return fmt.Errorf("invalidate password reset tokens for user (tx): %w", err)
	}

	return nil
}

func scanResetToken(row pgx.Row) (*domain.PasswordResetToken, error) {
	var t domain.PasswordResetToken

	err := row.Scan(&t.ID, &t.UserID, &t.TokenHash, &t.ExpiresAt, &t.UsedAt, &t.CreatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// Not-found → same generic error as expired/used (no oracle).
			return nil, domain.ErrInvalidResetToken
		}

		return nil, fmt.Errorf("scan password reset token: %w", err)
	}

	return &t, nil
}
