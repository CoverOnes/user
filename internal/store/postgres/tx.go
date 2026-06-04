package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/CoverOnes/user/internal/domain"
	"github.com/CoverOnes/user/internal/store"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// TxManager implements service.Transactioner using a pgxpool.Pool.
// It wraps the pool's Begin/Commit/Rollback cycle and hands transactional
// UserStore and CompanyStore views to the callback (F5 — atomic Register).
type TxManager struct {
	pool *pgxpool.Pool
}

// NewTxManager returns a TxManager backed by the given pool.
func NewTxManager(pool *pgxpool.Pool) *TxManager {
	return &TxManager{pool: pool}
}

// WithTx runs fn inside a single DB transaction.
// If fn returns an error the transaction is rolled back; otherwise it is committed.
// The callback receives transactional views of the user, company, and email
// verification-token stores so Register can atomically create user + company +
// hashed verification token (F5 / Increment 1).
func (m *TxManager) WithTx(
	ctx context.Context,
	fn func(
		ctx context.Context,
		users store.UserStore,
		companies store.CompanyStore,
		verifications store.EmailVerificationTokenStore,
	) error,
) error {
	tx, err := m.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}

	defer func() {
		// Rollback is a no-op after Commit.
		if rbErr := tx.Rollback(ctx); rbErr != nil && !errors.Is(rbErr, pgx.ErrTxClosed) {
			// Log is intentionally omitted here — callers see the original fn error.
			_ = rbErr
		}
	}()

	txUsers := &txUserStore{tx: tx}
	txCompanies := &txCompanyStore{tx: tx}
	txVerifications := &txVerificationStore{tx: tx}

	if fnErr := fn(ctx, txUsers, txCompanies, txVerifications); fnErr != nil {
		return fnErr
	}

	if commitErr := tx.Commit(ctx); commitErr != nil {
		return fmt.Errorf("commit transaction: %w", commitErr)
	}

	return nil
}

// txExecer is the minimal interface satisfied by both pgx.Tx and pgxpool.Pool.
type txExecer interface {
	Exec(ctx context.Context, sql string, arguments ...any) (pgconn.CommandTag, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// txUserStore is a UserStore that operates within a pgx.Tx.
type txUserStore struct {
	tx txExecer
}

func (s *txUserStore) Create(ctx context.Context, u *domain.User) error {
	_, err := s.tx.Exec(
		ctx, userInsertSQL,
		u.ID, u.Email, u.PasswordHash, u.DisplayName, u.AvatarURL,
		u.AccountType, u.KYCTier, u.CompanyID, u.Status, u.EmailVerified,
		u.LegalNameEnc, u.NationalIDEnc, u.TokenVersion, u.CreatedAt, u.UpdatedAt,
	)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return domain.ErrEmailTaken
		}

		return fmt.Errorf("insert user (tx): %w", err)
	}

	return nil
}

func (s *txUserStore) GetByID(ctx context.Context, id uuid.UUID) (*domain.User, error) {
	q := `SELECT ` + userSelectColumns + ` FROM users WHERE id = $1 AND deleted_at IS NULL`

	return scanUser(s.tx.QueryRow(ctx, q, id))
}

func (s *txUserStore) GetByEmail(ctx context.Context, email string) (*domain.User, error) {
	q := `SELECT ` + userSelectColumns + ` FROM users WHERE email = $1 AND deleted_at IS NULL`

	return scanUser(s.tx.QueryRow(ctx, q, email))
}

func (s *txUserStore) UpdateProfile(ctx context.Context, id uuid.UUID, displayName string, avatarURL *string) error {
	q := `
	UPDATE users
	SET display_name = $2, avatar_url = $3, updated_at = now()
	WHERE id = $1 AND deleted_at IS NULL
	`

	tag, err := s.tx.Exec(ctx, q, id, displayName, avatarURL)
	if err != nil {
		return fmt.Errorf("update user profile (tx): %w", err)
	}

	if tag.RowsAffected() == 0 {
		return domain.ErrNotFound
	}

	return nil
}

func (s *txUserStore) UpdateKYCTier(ctx context.Context, id uuid.UUID, tier int16) error {
	q := `
	UPDATE users
	SET kyc_tier = $2, updated_at = now()
	WHERE id = $1 AND deleted_at IS NULL
	`

	tag, err := s.tx.Exec(ctx, q, id, tier)
	if err != nil {
		return fmt.Errorf("update kyc_tier (tx): %w", err)
	}

	if tag.RowsAffected() == 0 {
		return domain.ErrNotFound
	}

	return nil
}

func (s *txUserStore) BumpTokenVersion(ctx context.Context, id uuid.UUID) (int, error) {
	q := `
	UPDATE users
	SET token_version = token_version + 1, updated_at = now()
	WHERE id = $1 AND deleted_at IS NULL
	RETURNING token_version
	`

	var newVersion int
	if err := s.tx.QueryRow(ctx, q, id).Scan(&newVersion); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, domain.ErrNotFound
		}

		return 0, fmt.Errorf("bump token_version (tx): %w", err)
	}

	return newVersion, nil
}

func (s *txUserStore) SetEmailVerified(ctx context.Context, id uuid.UUID) error {
	q := `UPDATE users SET email_verified = true, updated_at = now() WHERE id = $1 AND deleted_at IS NULL`

	tag, err := s.tx.Exec(ctx, q, id)
	if err != nil {
		return fmt.Errorf("set email_verified (tx): %w", err)
	}

	if tag.RowsAffected() == 0 {
		return domain.ErrNotFound
	}

	return nil
}

func (s *txUserStore) SetPendingTOTPSecret(ctx context.Context, id uuid.UUID, secretEnc []byte) error {
	q := `UPDATE users SET totp_secret_enc = $2, updated_at = now() WHERE id = $1 AND deleted_at IS NULL`

	tag, err := s.tx.Exec(ctx, q, id, secretEnc)
	if err != nil {
		return fmt.Errorf("set pending totp secret (tx): %w", err)
	}

	if tag.RowsAffected() == 0 {
		return domain.ErrNotFound
	}

	return nil
}

// EnableMFA mirrors UserStore.EnableMFA: an ATOMIC + CONDITIONAL (mfa_enabled = false)
// write that closes the TOCTOU window (CWE-367). The CTE separates not-found from
// already-enabled so a second concurrent Confirm gets ErrMFAAlreadyEnabled rather than
// silently overwriting the first backup-code set. See user_store.go for the full rationale.
func (s *txUserStore) EnableMFA(ctx context.Context, id uuid.UUID, backupCodesEnc []byte, enrolledAt time.Time) error {
	q := `
	WITH target AS (
		SELECT id FROM users WHERE id = $1 AND deleted_at IS NULL
	), upd AS (
		UPDATE users
		SET mfa_enabled = true, mfa_backup_codes_enc = $2, mfa_enrolled_at = $3, updated_at = now()
		WHERE id = $1 AND deleted_at IS NULL AND mfa_enabled = false
		RETURNING id
	)
	SELECT
		(SELECT count(*) FROM target) AS existed,
		(SELECT count(*) FROM upd)    AS updated`

	var existed, updated int
	if err := s.tx.QueryRow(ctx, q, id, backupCodesEnc, enrolledAt).Scan(&existed, &updated); err != nil {
		return fmt.Errorf("enable mfa (tx): %w", err)
	}

	if existed == 0 {
		return domain.ErrNotFound
	}
	if updated == 0 {
		return domain.ErrMFAAlreadyEnabled
	}

	return nil
}

func (s *txUserStore) DisableMFA(ctx context.Context, id uuid.UUID) error {
	q := `
	UPDATE users
	SET mfa_enabled = false, totp_secret_enc = NULL, mfa_backup_codes_enc = NULL,
	    mfa_enrolled_at = NULL, updated_at = now()
	WHERE id = $1 AND deleted_at IS NULL`

	tag, err := s.tx.Exec(ctx, q, id)
	if err != nil {
		return fmt.Errorf("disable mfa (tx): %w", err)
	}

	if tag.RowsAffected() == 0 {
		return domain.ErrNotFound
	}

	return nil
}

func (s *txUserStore) SetMFABackupCodes(ctx context.Context, id uuid.UUID, backupCodesEnc []byte) error {
	q := `UPDATE users SET mfa_backup_codes_enc = $2, updated_at = now() WHERE id = $1 AND deleted_at IS NULL`

	tag, err := s.tx.Exec(ctx, q, id, backupCodesEnc)
	if err != nil {
		return fmt.Errorf("set mfa backup codes (tx): %w", err)
	}

	if tag.RowsAffected() == 0 {
		return domain.ErrNotFound
	}

	return nil
}

// txCompanyStore is a CompanyStore that operates within a pgx.Tx.
type txCompanyStore struct {
	tx txExecer
}

func (s *txCompanyStore) Create(ctx context.Context, c *domain.Company) error {
	q := `
	INSERT INTO companies
		(id, name, registration_no, owner_user_id, status, created_at, updated_at)
	VALUES ($1, $2, $3, $4, $5, $6, $7)
	`

	_, err := s.tx.Exec(
		ctx, q,
		c.ID, c.Name, c.RegistrationNo, c.OwnerUserID,
		c.Status, c.CreatedAt, c.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("insert company (tx): %w", err)
	}

	return nil
}

func (s *txCompanyStore) GetByID(ctx context.Context, id uuid.UUID) (*domain.Company, error) {
	q := `
	SELECT id, name, registration_no, owner_user_id, status, created_at, updated_at
	FROM companies
	WHERE id = $1
	`

	var co domain.Company

	err := s.tx.QueryRow(ctx, q, id).Scan(
		&co.ID, &co.Name, &co.RegistrationNo, &co.OwnerUserID,
		&co.Status, &co.CreatedAt, &co.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domain.ErrNotFound
		}

		return nil, fmt.Errorf("scan company (tx): %w", err)
	}

	return &co, nil
}
