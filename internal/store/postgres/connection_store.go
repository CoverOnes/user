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

// connectionPairLiveUniqIndex is the name of the partial-unique index that enforces
// "at most one LIVE (pending|accepted) edge per unordered pair" (migration 000010).
// A 23505 carrying this constraint name is mapped to domain.ErrConnectionExists; any
// other 23505 is surfaced as a wrapped error so an unrelated future unique constraint
// is never misreported.
const connectionPairLiveUniqIndex = "connections_pair_live_uniq"

// ConnectionStore implements store.ConnectionStore backed by Postgres.
type ConnectionStore struct {
	pool *pgxpool.Pool
}

// NewConnectionStore returns a new ConnectionStore.
func NewConnectionStore(pool *pgxpool.Pool) *ConnectionStore {
	return &ConnectionStore{pool: pool}
}

// Create inserts a new pending connection edge. A live edge already covering the
// unordered pair violates connections_pair_live_uniq (23505) → ErrConnectionExists.
// The partial-unique index is the race-safe authority — we NEVER pre-check then
// insert (TOCTOU-safe).
func (s *ConnectionStore) Create(ctx context.Context, c *domain.Connection) error {
	q := `
	INSERT INTO connections (id, requester_id, addressee_id, status, created_at, updated_at)
	VALUES ($1, $2, $3, $4, $5, $6)
	`

	_, err := s.pool.Exec(ctx, q, c.ID, c.RequesterID, c.AddresseeID, c.Status, c.CreatedAt, c.UpdatedAt)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" && pgErr.ConstraintName == connectionPairLiveUniqIndex {
			return domain.ErrConnectionExists
		}

		return fmt.Errorf("insert connection: %w", err)
	}

	return nil
}

// connectionUserColumns is the EXPLICIT PII-safe projection of the OTHER party in a
// connection card. It lists ONLY non-PII public columns (mirrors the public-profile
// allowlist). PII columns (email, national_id_enc, legal_name_enc, kyc_tier, status,
// …) are deliberately excluded so a connection list can never leak them. The `o`
// alias is the "other user" join target; `c` is the connections row.
const connectionUserColumns = `
	c.id,
	o.id, o.display_name, o.handle, o.headline, o.avatar_url, o.account_type`

// scanConnectionWithUser scans the connectionUserColumns projection plus a trailing
// timestamp column into a store.ConnectionWithUser. The column order MUST stay in
// lockstep with connectionUserColumns + the per-query timestamp expression.
func scanConnectionWithUser(row pgx.Row) (store.ConnectionWithUser, error) {
	var cu store.ConnectionWithUser

	err := row.Scan(
		&cu.ID,
		&cu.OtherUserID, &cu.DisplayName, &cu.Handle, &cu.Headline, &cu.AvatarURL, &cu.AccountType,
		&cu.Timestamp,
	)
	if err != nil {
		return store.ConnectionWithUser{}, fmt.Errorf("scan connection with user: %w", err)
	}

	return cu, nil
}

// collectConnectionsWithUser runs q (which MUST select connectionUserColumns + a
// timestamp) bound to args and returns the scanned rows.
func (s *ConnectionStore) collectConnectionsWithUser(ctx context.Context, q string, args ...any) ([]store.ConnectionWithUser, error) {
	rows, err := s.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("query connections: %w", err)
	}

	defer rows.Close()

	var out []store.ConnectionWithUser

	for rows.Next() {
		cu, scanErr := scanConnectionWithUser(rows)
		if scanErr != nil {
			return nil, scanErr
		}

		out = append(out, cu)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate connections: %w", err)
	}

	return out, nil
}

// ListAcceptedForUser returns every ACCEPTED connection for uid. The OTHER party is
// resolved via CASE (requester_id=$1 → addressee_id, else requester_id) and joined
// to users with the PII-safe projection, EXCLUDING soft-deleted users
// (o.deleted_at IS NULL). Ordered newest-accepted-first by updated_at.
func (s *ConnectionStore) ListAcceptedForUser(ctx context.Context, uid uuid.UUID) ([]store.ConnectionWithUser, error) {
	q := `
	SELECT ` + connectionUserColumns + `, c.updated_at
	FROM connections c
	JOIN users o
	  ON o.id = CASE WHEN c.requester_id = $1 THEN c.addressee_id ELSE c.requester_id END
	WHERE c.status = 'accepted'
	  AND (c.requester_id = $1 OR c.addressee_id = $1)
	  AND o.deleted_at IS NULL
	ORDER BY c.updated_at DESC
	`

	return s.collectConnectionsWithUser(ctx, q, uid)
}

// ListPendingForUser returns the user's pending invites in two slices:
//   - incoming: uid is the addressee (someone invited the caller); OTHER = requester
//   - outgoing: uid is the requester (the caller invited someone); OTHER = addressee
//
// Both project the OTHER party's PII-safe columns from live users only and are
// ordered newest-first by created_at.
func (s *ConnectionStore) ListPendingForUser(ctx context.Context, uid uuid.UUID) (incoming, outgoing []store.ConnectionWithUser, err error) {
	incomingQ := `
	SELECT ` + connectionUserColumns + `, c.created_at
	FROM connections c
	JOIN users o ON o.id = c.requester_id
	WHERE c.status = 'pending'
	  AND c.addressee_id = $1
	  AND o.deleted_at IS NULL
	ORDER BY c.created_at DESC
	`

	outgoingQ := `
	SELECT ` + connectionUserColumns + `, c.created_at
	FROM connections c
	JOIN users o ON o.id = c.addressee_id
	WHERE c.status = 'pending'
	  AND c.requester_id = $1
	  AND o.deleted_at IS NULL
	ORDER BY c.created_at DESC
	`

	incoming, err = s.collectConnectionsWithUser(ctx, incomingQ, uid)
	if err != nil {
		return nil, nil, fmt.Errorf("list incoming pending: %w", err)
	}

	outgoing, err = s.collectConnectionsWithUser(ctx, outgoingQ, uid)
	if err != nil {
		return nil, nil, fmt.Errorf("list outgoing pending: %w", err)
	}

	return incoming, outgoing, nil
}

// resolvePendingInvite is the shared guarded-UPDATE for accept/decline. The WHERE
// clause (id = $1 AND addressee_id = $2 AND status = 'pending') IS the authorization
// boundary: only the addressee can resolve their own pending invite, and only once.
//
// A CTE distinguishes the three outcomes from a single round-trip (mirrors the
// EnableMFA CTE pattern in user_store.go):
//   - no row addressed to addresseeID with this id → ErrConnectionNotFound (IDOR-safe 404)
//   - addressed to addresseeID but already resolved → ErrConnectionNotPending (409)
//   - row flipped to newStatus                      → nil
//
// `target` matches the id+addressee pair regardless of status (so we can tell apart
// "not yours / no such id" from "yours but already resolved"); `upd` performs the
// pending-guarded write.
func (s *ConnectionStore) resolvePendingInvite(ctx context.Context, id, addresseeID uuid.UUID, newStatus string) error {
	q := `
	WITH target AS (
		SELECT id FROM connections WHERE id = $1 AND addressee_id = $2
	), upd AS (
		UPDATE connections
		SET status = $3, updated_at = now()
		WHERE id = $1 AND addressee_id = $2 AND status = 'pending'
		RETURNING id
	)
	SELECT
		(SELECT count(*) FROM target) AS existed,
		(SELECT count(*) FROM upd)    AS updated
	`

	var existed, updated int
	if err := s.pool.QueryRow(ctx, q, id, addresseeID, newStatus).Scan(&existed, &updated); err != nil {
		return fmt.Errorf("resolve pending invite: %w", err)
	}

	if existed == 0 {
		// No invite with this id addressed to this user. Same error whether the id is
		// unknown or belongs to someone else — no oracle that leaks edge existence.
		return domain.ErrConnectionNotFound
	}

	if updated == 0 {
		// Addressed to this user but the pending guard failed → already resolved.
		return domain.ErrConnectionNotPending
	}

	return nil
}

// AcceptInvite flips a pending invite addressed to addresseeID to 'accepted'.
func (s *ConnectionStore) AcceptInvite(ctx context.Context, id, addresseeID uuid.UUID) error {
	return s.resolvePendingInvite(ctx, id, addresseeID, domain.ConnectionStatusAccepted)
}

// DeclineInvite flips a pending invite addressed to addresseeID to 'declined'.
func (s *ConnectionStore) DeclineInvite(ctx context.Context, id, addresseeID uuid.UUID) error {
	return s.resolvePendingInvite(ctx, id, addresseeID, domain.ConnectionStatusDeclined)
}
