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

// handleUniqueIndex is the name of the partial-unique index on users.handle
// (migration 000009). A 23505 violation carrying this constraint name is mapped
// to domain.ErrHandleTaken; any other 23505 is surfaced as a wrapped error.
const handleUniqueIndex = "users_handle_unique"

// updateProfileSQL is the shared UPDATE used by both the pool-backed UserStore and
// the transactional txUserStore so the column list stays in lockstep. It performs a
// FULL replace of the editable public-profile fields (nil *string clears the column).
const updateProfileSQL = `
	UPDATE users
	SET display_name = $2, handle = $3, headline = $4, bio = $5,
	    location = $6, avatar_url = $7, cover_url = $8, updated_at = now()
	WHERE id = $1 AND deleted_at IS NULL
	`

// isHandleTaken reports whether err is a Postgres 23505 unique-violation on the
// users_handle_unique index. Matching on the constraint name (not just the SQLSTATE)
// keeps the mapping precise: an unrelated future unique constraint won't be
// misreported as ErrHandleTaken.
func isHandleTaken(err error) bool {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		return pgErr.ConstraintName == handleUniqueIndex
	}

	return false
}

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
// The trailing public-profile columns (handle..cover_url) were added in 000009;
// they MUST stay in lockstep with scanUser's Scan call below.
const userSelectColumns = `
		id, email, password_hash, display_name, avatar_url, account_type,
		kyc_tier, company_id, status, email_verified,
		legal_name_enc, national_id_enc,
		mfa_enabled, totp_secret_enc, mfa_backup_codes_enc, mfa_enrolled_at,
		token_version, deleted_at, created_at, updated_at,
		handle, headline, bio, location, cover_url`

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

// UpdateProfile replaces the editable public-profile fields, bumping updated_at.
// A 23505 unique-violation on users_handle_unique maps to domain.ErrHandleTaken
// (the partial-unique index is the race-safe authority — we never pre-check then
// insert). RowsAffected()==0 means no live row matched → domain.ErrNotFound.
func (s *UserStore) UpdateProfile(ctx context.Context, id uuid.UUID, in store.ProfileUpdate) error {
	tag, err := s.pool.Exec(
		ctx, updateProfileSQL,
		id, in.DisplayName, in.Handle, in.Headline, in.Bio, in.Location, in.AvatarURL, in.CoverURL,
	)
	if err != nil {
		if isHandleTaken(err) {
			return domain.ErrHandleTaken
		}

		return fmt.Errorf("update user profile: %w", err)
	}

	if tag.RowsAffected() == 0 {
		return domain.ErrNotFound
	}

	return nil
}

// UpdateKYCTier monotonically advances kyc_tier for the given user, bumping
// updated_at. "Monotonic" means the tier is only written when newTier is strictly
// greater than the stored value — a stale or replayed event with an equal or lower
// tier is silently ignored (returns nil, not an error), preventing KYC downgrades
// from replays. ErrNotFound is returned only when no live row matches the user ID.
//
// A CTE distinguishes the two 0-row outcomes in a single round-trip:
//   - row exists but kyc_tier >= newTier → tier not advanced; return nil (no-op).
//   - no live row at all                 → ErrNotFound.
func (s *UserStore) UpdateKYCTier(ctx context.Context, id uuid.UUID, tier int16) error {
	q := `
	WITH target AS (
		SELECT id FROM users WHERE id = $1 AND deleted_at IS NULL
	), upd AS (
		UPDATE users
		SET kyc_tier = $2, updated_at = now()
		WHERE id = $1 AND deleted_at IS NULL AND kyc_tier < $2
		RETURNING id
	)
	SELECT
		(SELECT count(*) FROM target) AS existed,
		(SELECT count(*) FROM upd)    AS updated
	`

	var existed, updated int64

	if err := s.pool.QueryRow(ctx, q, id, tier).Scan(&existed, &updated); err != nil {
		return fmt.Errorf("update kyc_tier: %w", err)
	}

	if existed == 0 {
		return domain.ErrNotFound
	}

	// existed > 0 but updated == 0 means tier was already >= newTier (stale/replay).
	// This is not an error — the monotonic guard silently absorbed the event.
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

// SetEmailVerified flips users.email_verified to true and promotes the account to
// at least Tier 1. Idempotent — re-running on an already-verified row succeeds
// (row count 1); ErrNotFound only when no live row matches.
func (s *UserStore) SetEmailVerified(ctx context.Context, id uuid.UUID) error {
	q := `
		UPDATE users
		SET email_verified = true,
		    kyc_tier = GREATEST(kyc_tier, 1),
		    updated_at = now()
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
//
// The UPDATE is ATOMIC + CONDITIONAL (mfa_enabled = false): it closes the TOCTOU window
// (CWE-367) where two concurrent Confirm calls both pass the service-layer
// GetByID→!MFAEnabled check and each writes a fresh backup-code set. Only ONE UPDATE can
// observe mfa_enabled = false, so only one backup-code set is ever persisted.
//
// A CTE distinguishes the three outcomes from a single round-trip:
//   - no row exists (unknown / soft-deleted user)  → ErrNotFound
//   - row exists but mfa_enabled was already true   → ErrMFAAlreadyEnabled
//   - row updated                                    → nil
//
// `target` selects the live row (or none); `upd` performs the guarded write and reports
// which ids it touched. We then read existed vs updated to pick the precise error.
func (s *UserStore) EnableMFA(ctx context.Context, id uuid.UUID, backupCodesEnc []byte, enrolledAt time.Time) error {
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
		(SELECT count(*) FROM upd)    AS updated
	`

	var existed, updated int
	if err := s.pool.QueryRow(ctx, q, id, backupCodesEnc, enrolledAt).Scan(&existed, &updated); err != nil {
		return fmt.Errorf("enable mfa: %w", err)
	}

	if existed == 0 {
		return domain.ErrNotFound
	}
	if updated == 0 {
		// Row exists but the guard (mfa_enabled = false) failed → already enabled.
		return domain.ErrMFAAlreadyEnabled
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

// SetPasswordHash replaces the stored Argon2id hash for the given user.
// Returns ErrNotFound if no live row matches (mirrors SetEmailVerified pattern).
func (s *UserStore) SetPasswordHash(ctx context.Context, id uuid.UUID, hash string) error {
	q := `
	UPDATE users
	SET password_hash = $2, updated_at = now()
	WHERE id = $1 AND deleted_at IS NULL
	`

	tag, err := s.pool.Exec(ctx, q, id, hash)
	if err != nil {
		return fmt.Errorf("set password hash: %w", err)
	}

	if tag.RowsAffected() == 0 {
		return domain.ErrNotFound
	}

	return nil
}

func scanUser(row pgx.Row) (*domain.User, error) {
	var u domain.User
	// password_hash is nullable since migration 000007 (OAuth-only accounts).
	err := row.Scan(
		&u.ID, &u.Email, &u.PasswordHash, &u.DisplayName, &u.AvatarURL,
		&u.AccountType, &u.KYCTier, &u.CompanyID, &u.Status, &u.EmailVerified,
		&u.LegalNameEnc, &u.NationalIDEnc,
		&u.MFAEnabled, &u.TOTPSecretEnc, &u.MFABackupCodesEnc, &u.MFAEnrolledAt,
		&u.TokenVersion,
		&u.DeletedAt, &u.CreatedAt, &u.UpdatedAt,
		&u.Handle, &u.Headline, &u.Bio, &u.Location, &u.CoverURL,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domain.ErrNotFound
		}

		return nil, fmt.Errorf("scan user: %w", err)
	}

	return &u, nil
}
