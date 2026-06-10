package postgres

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/CoverOnes/user/internal/domain"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

// RefreshTokenStore implements store.RefreshTokenStore backed by Postgres.
type RefreshTokenStore struct {
	pool *pgxpool.Pool
}

// NewRefreshTokenStore returns a new RefreshTokenStore.
func NewRefreshTokenStore(pool *pgxpool.Pool) *RefreshTokenStore {
	return &RefreshTokenStore{pool: pool}
}

// Create inserts a new refresh_token row.
func (s *RefreshTokenStore) Create(ctx context.Context, rt *domain.RefreshToken) error {
	q := `
	INSERT INTO refresh_tokens
		(id, user_id, family_id, token_hash, prev_id, used_at, revoked_at,
		 device_fingerprint, ip_addr, user_agent, expires_at, created_at, token_version)
	VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
	`

	var ipText *string
	if rt.IPAddr.IsValid() {
		s := rt.IPAddr.String()
		ipText = &s
	}

	_, err := s.pool.Exec(
		ctx, q,
		rt.ID, rt.UserID, rt.FamilyID, rt.TokenHash, rt.PrevID,
		rt.UsedAt, rt.RevokedAt,
		rt.DeviceFingerprint, ipText, rt.UserAgent,
		rt.ExpiresAt, rt.CreatedAt, rt.TokenVersion,
	)
	if err != nil {
		return fmt.Errorf("insert refresh_token: %w", err)
	}

	return nil
}

// GetByID fetches a refresh token row by PK.
func (s *RefreshTokenStore) GetByID(ctx context.Context, id uuid.UUID) (*domain.RefreshToken, error) {
	// Cast ip_addr to text for portable scanning; pgx cannot scan inet into *string directly.
	q := `
	SELECT id, user_id, family_id, token_hash, prev_id, used_at, revoked_at,
	       device_fingerprint, ip_addr::text, user_agent, expires_at, created_at, token_version
	FROM refresh_tokens
	WHERE id = $1
	`

	row := s.pool.QueryRow(ctx, q, id)

	return scanRefreshToken(row)
}

// MarkUsed atomically marks a token as consumed via a CAS (compare-and-swap) on
// used_at IS NULL. It returns (true, nil) when the row was successfully flipped
// from unused to used (exactly one row affected). It returns (false, nil) when
// used_at was already set — indicating a concurrent reuse attempt — so the caller
// can trigger family revocation without a separate round-trip. Any DB error is
// wrapped and returned with ok=false.
//
// The CAS mirrors MarkConsumed in verification_store.go which uses the identical
// WHERE id=$1 AND consumed_at IS NULL pattern.
func (s *RefreshTokenStore) MarkUsed(ctx context.Context, id uuid.UUID, now time.Time) (bool, error) {
	q := `UPDATE refresh_tokens SET used_at = $2, revoked_at = $2 WHERE id = $1 AND used_at IS NULL`

	tag, err := s.pool.Exec(ctx, q, id, now)
	if err != nil {
		return false, fmt.Errorf("mark refresh token used: %w", err)
	}

	return tag.RowsAffected() > 0, nil
}

// RevokeFamily sets revoked_at on all live rows in the same token family.
func (s *RefreshTokenStore) RevokeFamily(ctx context.Context, familyID uuid.UUID, now time.Time) error {
	q := `UPDATE refresh_tokens SET revoked_at = $2 WHERE family_id = $1 AND revoked_at IS NULL`

	_, err := s.pool.Exec(ctx, q, familyID, now)
	if err != nil {
		return fmt.Errorf("revoke token family: %w", err)
	}

	return nil
}

func scanRefreshToken(row pgx.Row) (*domain.RefreshToken, error) {
	var rt domain.RefreshToken
	var ipText *string
	var prevID pgtype.UUID

	err := row.Scan(
		&rt.ID, &rt.UserID, &rt.FamilyID, &rt.TokenHash, &prevID,
		&rt.UsedAt, &rt.RevokedAt,
		&rt.DeviceFingerprint, &ipText, &rt.UserAgent,
		&rt.ExpiresAt, &rt.CreatedAt, &rt.TokenVersion,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domain.ErrInvalidRefresh
		}

		return nil, fmt.Errorf("scan refresh_token: %w", err)
	}

	if prevID.Valid {
		uid := uuid.UUID(prevID.Bytes)
		rt.PrevID = &uid
	}

	if ipText != nil && *ipText != "" {
		ipStr := *ipText
		// Postgres inet::text may include CIDR suffix (e.g. "192.168.1.100/32").
		// Strip the prefix if present for pure-address parsing.
		if idx := strings.Index(ipStr, "/"); idx >= 0 {
			ipStr = ipStr[:idx]
		}

		addr, parseErr := netip.ParseAddr(ipStr)
		if parseErr == nil {
			rt.IPAddr = addr
		}
	}

	return &rt, nil
}
