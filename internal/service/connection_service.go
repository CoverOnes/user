package service

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/CoverOnes/user/internal/domain"
	"github.com/CoverOnes/user/internal/store"
	"github.com/google/uuid"
)

// ConnectionService holds the business logic for the P4 Network connections
// aggregate. It validates referential integrity in code (no FK, red-line #9): a
// SendInvite confirms the target user exists and is live before inserting an edge.
type ConnectionService struct {
	users store.UserStore
	conns store.ConnectionStore
}

// NewConnectionService creates a ConnectionService.
func NewConnectionService(users store.UserStore, conns store.ConnectionStore) *ConnectionService {
	return &ConnectionService{users: users, conns: conns}
}

// SendInvite creates a pending connection from requesterID to addresseeID.
//
// Order of checks:
//  1. self-invite (addressee == requester) → ErrValidation (400) — cheap, no DB hit.
//  2. addressee must be a live user (referential integrity in code, since there is
//     no FK): users.GetByID returns ErrNotFound for an absent/soft-deleted user,
//     which is surfaced as-is → USER_NOT_FOUND (404).
//  3. conns.Create — the partial-unique index is the race-safe authority for the
//     "live edge already exists" case (→ ErrConnectionExists / 409); we never
//     check-then-insert.
//
// Returns the created edge on success.
func (s *ConnectionService) SendInvite(ctx context.Context, requesterID, addresseeID uuid.UUID) (*domain.Connection, error) {
	if requesterID == addresseeID {
		return nil, fmt.Errorf("%w: cannot connect to yourself", domain.ErrValidation)
	}

	// Referential-integrity-in-code: the addressee must exist and be live. GetByID
	// already filters deleted_at IS NULL, so a soft-deleted target yields ErrNotFound.
	if _, err := s.users.GetByID(ctx, addresseeID); err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return nil, domain.ErrNotFound
		}

		return nil, fmt.Errorf("lookup addressee: %w", err)
	}

	now := time.Now().UTC()
	c := &domain.Connection{
		ID:          uuid.New(),
		RequesterID: requesterID,
		AddresseeID: addresseeID,
		Status:      domain.ConnectionStatusPending,
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	if err := s.conns.Create(ctx, c); err != nil {
		// ErrConnectionExists (live-edge 23505) is surfaced as-is → 409.
		return nil, err
	}

	return c, nil
}

// ListAccepted returns the caller's accepted connections (PII-safe projection).
func (s *ConnectionService) ListAccepted(ctx context.Context, uid uuid.UUID) ([]store.ConnectionWithUser, error) {
	return s.conns.ListAcceptedForUser(ctx, uid)
}

// ListPending returns the caller's pending invites split into incoming/outgoing.
func (s *ConnectionService) ListPending(ctx context.Context, uid uuid.UUID) (incoming, outgoing []store.ConnectionWithUser, err error) {
	return s.conns.ListPendingForUser(ctx, uid)
}

// Accept resolves a pending invite addressed to callerID to 'accepted'. Authorization
// is enforced entirely in the SQL guard (addressee_id = callerID AND status =
// 'pending'), so there is no read-then-write TOCTOU window and no IDOR oracle: a
// wrong-addressee or unknown id both return ErrConnectionNotFound (404).
func (s *ConnectionService) Accept(ctx context.Context, id, callerID uuid.UUID) error {
	return s.conns.AcceptInvite(ctx, id, callerID)
}

// Decline resolves a pending invite addressed to callerID to 'declined' under the
// same SQL-guard authorization as Accept.
func (s *ConnectionService) Decline(ctx context.Context, id, callerID uuid.UUID) error {
	return s.conns.DeclineInvite(ctx, id, callerID)
}
