package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/CoverOnes/user/internal/domain"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// UserStore implements store.UserStore backed by Postgres.
type UserStore struct {
	pool *pgxpool.Pool
}

// NewUserStore returns a new UserStore.
func NewUserStore(pool *pgxpool.Pool) *UserStore {
	return &UserStore{pool: pool}
}

// userInsertSQL is the shared INSERT used by both the pool-backed UserStore and
// the transactional txUserStore so the column list stays in lockstep.
const userInsertSQL = `
	INSERT INTO users
		(id, email, password_hash, display_name, avatar_url, account_type,
		 kyc_tier, company_id, status, email_verified,
		 legal_name_enc, national_id_enc, token_version, created_at, updated_at)
	VALUES
		($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
	`

// userSelectColumns is the shared SELECT column list consumed by scanUser.
const userSelectColumns = `
		id, email, password_hash, display_name, avatar_url, account_type,
		kyc_tier, company_id, status, email_verified,
		legal_name_enc, national_id_enc,
		mfa_enabled, totp_secret_enc, mfa_backup_codes_enc, mfa_enrolled_at,
		token_version, deleted_at, created_at, updated_at`

// Create inserts a new user row.
func (s *UserStore) Create(ctx context.Context, u *domain.User) error {
	_, err := s.pool.Exec(
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

		return fmt.Errorf("insert user: %w", err)
	}

	return nil
}

// GetByID fetches a live (non-deleted) user by PK.
func (s *UserStore) GetByID(ctx context.Context, id uuid.UUID) (*domain.User, error) {
	q := `SELECT ` + userSelectColumns + ` FROM users WHERE id = $1 AND deleted_at IS NULL`

	return scanUser(s.pool.QueryRow(ctx, q, id))
}

// GetByEmail fetches a live user by email (case-insensitive via citext).
func (s *UserStore) GetByEmail(ctx context.Context, email string) (*domain.User, error) {
	q := `SELECT ` + userSelectColumns + ` FROM users WHERE email = $1 AND deleted_at IS NULL`

	return scanUser(s.pool.QueryRow(ctx, q, email))
}

// UpdateProfile updates displayName and avatarUrl, bumping updated_at.
func (s *UserStore) UpdateProfile(ctx context.Context, id uuid.UUID, displayName string, avatarURL *string) error {
	q := `
	UPDATE users
	SET display_name = $2, avatar_url = $3, updated_at = now()
	WHERE id = $1 AND deleted_at IS NULL
	`

	tag, err := s.pool.Exec(ctx, q, id, displayName, avatarURL)
	if err != nil {
		return fmt.Errorf("update user profile: %w", err)
	}

	if tag.RowsAffected() == 0 {
		return domain.ErrNotFound
	}

	return nil
}

// UpdateKYCTier sets kyc_tier for the given user, bumping updated_at.
// Called by the Redis consumer on kyc.tier_changed events.
func (s *UserStore) UpdateKYCTier(ctx context.Context, id uuid.UUID, tier int16) error {
	q := `
	UPDATE users
	SET kyc_tier = $2, updated_at = now()
	WHERE id = $1 AND deleted_at IS NULL
	`

	tag, err := s.pool.Exec(ctx, q, id, tier)
	if err != nil {
		return fmt.Errorf("update kyc_tier: %w", err)
	}

	if tag.RowsAffected() == 0 {
		return domain.ErrNotFound
	}

	return nil
}

// BumpTokenVersion atomically increments token_version and returns the new value.
// This forces all existing refresh tokens (which carry the previous version) to fail
// the server-side version check on next use, effectively revoking every session.
func (s *UserStore) BumpTokenVersion(ctx context.Context, id uuid.UUID) (int, error) {
	q := `
	UPDATE users
	SET token_version = token_version + 1, updated_at = now()
	WHERE id = $1 AND deleted_at IS NULL
	RETURNING token_version
	`

	var newVersion int
	if err := s.pool.QueryRow(ctx, q, id).Scan(&newVersion); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, domain.ErrNotFound
		}

		return 0, fmt.Errorf("bump token_version: %w", err)
	}

	return newVersion, nil
}

// SetEmailVerified flips users.email_verified to true. Idempotent — re-running
// on an already-verified row succeeds (row count 1); ErrNotFound only when no
// live row matches.
func (s *UserStore) SetEmailVerified(ctx context.Context, id uuid.UUID) error {
	q := `
	UPDATE users
	SET email_verified = true, updated_at = now()
	WHERE id = $1 AND deleted_at IS NULL
	`

	tag, err := s.pool.Exec(ctx, q, id)
	if err != nil {
		return fmt.Errorf("set email_verified: %w", err)
	}

	if tag.RowsAffected() == 0 {
		return domain.ErrNotFound
	}

	return nil
}

// SetPendingTOTPSecret writes the encrypted PENDING TOTP secret without enabling
// MFA. A re-enroll overwrites the previous secret (so a stale pending secret can
// never be confirmed after a new enroll). Does NOT touch mfa_enabled.
func (s *UserStore) SetPendingTOTPSecret(ctx context.Context, id uuid.UUID, secretEnc []byte) error {
	q := `
	UPDATE users
	SET totp_secret_enc = $2, updated_at = now()
	WHERE id = $1 AND deleted_at IS NULL
	`

	tag, err := s.pool.Exec(ctx, q, id, secretEnc)
	if err != nil {
		return fmt.Errorf("set pending totp secret: %w", err)
	}

	if tag.RowsAffected() == 0 {
		return domain.ErrNotFound
	}

	return nil
}

// EnableMFA flips mfa_enabled=true, stores the encrypted backup codes, and stamps
// mfa_enrolled_at. The pending secret already in totp_secret_enc becomes the active
// secret. Called by confirm only after the submitted code verified.
func (s *UserStore) EnableMFA(ctx context.Context, id uuid.UUID, backupCodesEnc []byte, enrolledAt time.Time) error {
	q := `
	UPDATE users
	SET mfa_enabled = true, mfa_backup_codes_enc = $2, mfa_enrolled_at = $3, updated_at = now()
	WHERE id = $1 AND deleted_at IS NULL
	`

	tag, err := s.pool.Exec(ctx, q, id, backupCodesEnc, enrolledAt)
	if err != nil {
		return fmt.Errorf("enable mfa: %w", err)
	}

	if tag.RowsAffected() == 0 {
		return domain.ErrNotFound
	}

	return nil
}

// DisableMFA clears every MFA column in one statement (mfa_enabled, the secret, the
// backup codes, and mfa_enrolled_at). Called by disable only after a current code
// verified.
func (s *UserStore) DisableMFA(ctx context.Context, id uuid.UUID) error {
	q := `
	UPDATE users
	SET mfa_enabled = false, totp_secret_enc = NULL, mfa_backup_codes_enc = NULL,
	    mfa_enrolled_at = NULL, updated_at = now()
	WHERE id = $1 AND deleted_at IS NULL
	`

	tag, err := s.pool.Exec(ctx, q, id)
	if err != nil {
		return fmt.Errorf("disable mfa: %w", err)
	}

	if tag.RowsAffected() == 0 {
		return domain.ErrNotFound
	}

	return nil
}

// SetMFABackupCodes overwrites only the encrypted backup codes (used when a
// one-time code is consumed and the remaining set is re-persisted).
func (s *UserStore) SetMFABackupCodes(ctx context.Context, id uuid.UUID, backupCodesEnc []byte) error {
	q := `
	UPDATE users
	SET mfa_backup_codes_enc = $2, updated_at = now()
	WHERE id = $1 AND deleted_at IS NULL
	`

	tag, err := s.pool.Exec(ctx, q, id, backupCodesEnc)
	if err != nil {
		return fmt.Errorf("set mfa backup codes: %w", err)
	}

	if tag.RowsAffected() == 0 {
		return domain.ErrNotFound
	}

	return nil
}

func scanUser(row pgx.Row) (*domain.User, error) {
	var u domain.User
	err := row.Scan(
		&u.ID, &u.Email, &u.PasswordHash, &u.DisplayName, &u.AvatarURL,
		&u.AccountType, &u.KYCTier, &u.CompanyID, &u.Status, &u.EmailVerified,
		&u.LegalNameEnc, &u.NationalIDEnc,
		&u.MFAEnabled, &u.TOTPSecretEnc, &u.MFABackupCodesEnc, &u.MFAEnrolledAt,
		&u.TokenVersion,
		&u.DeletedAt, &u.CreatedAt, &u.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domain.ErrNotFound
		}

		return nil, fmt.Errorf("scan user: %w", err)
	}

	return &u, nil
}
