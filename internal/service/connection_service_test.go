package service_test

import (
	"context"
	"testing"
	"time"

	"github.com/CoverOnes/user/internal/domain"
	"github.com/CoverOnes/user/internal/service"
	"github.com/CoverOnes/user/internal/store"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeConnectionStore is an in-memory ConnectionStore for ConnectionService unit
// tests, with per-method error injection and a record of the last Create so a test
// can assert the constructed edge. The list/resolve paths are exercised by the
// Postgres integration test (the guarded-UPDATE / partial-unique semantics live in
// SQL); this fake only needs enough behavior to drive the service-layer branches.
type fakeConnectionStore struct {
	createErr  error
	acceptErr  error
	declineErr error

	created    *domain.Connection
	acceptedID uuid.UUID
	acceptedBy uuid.UUID

	accepted []store.ConnectionWithUser
	incoming []store.ConnectionWithUser
	outgoing []store.ConnectionWithUser
	listErr  error
}

func (f *fakeConnectionStore) Create(_ context.Context, c *domain.Connection) error {
	if f.createErr != nil {
		return f.createErr
	}

	cp := *c
	f.created = &cp

	return nil
}

func (f *fakeConnectionStore) ListAcceptedForUser(_ context.Context, _ uuid.UUID) ([]store.ConnectionWithUser, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}

	return f.accepted, nil
}

func (f *fakeConnectionStore) ListPendingForUser(_ context.Context, _ uuid.UUID) (incoming, outgoing []store.ConnectionWithUser, err error) {
	if f.listErr != nil {
		return nil, nil, f.listErr
	}

	return f.incoming, f.outgoing, nil
}

func (f *fakeConnectionStore) AcceptInvite(_ context.Context, id, addresseeID uuid.UUID) error {
	if f.acceptErr != nil {
		return f.acceptErr
	}

	f.acceptedID = id
	f.acceptedBy = addresseeID

	return nil
}

func (f *fakeConnectionStore) DeclineInvite(_ context.Context, id, addresseeID uuid.UUID) error {
	if f.declineErr != nil {
		return f.declineErr
	}

	f.acceptedID = id
	f.acceptedBy = addresseeID

	return nil
}

// seedConnUser inserts a live user into the shared fakeUserStore for connection tests.
func seedConnUser(t *testing.T, users *fakeUserStore, email string) *domain.User {
	t.Helper()

	now := time.Now().UTC()
	u := &domain.User{
		ID:          uuid.New(),
		Email:       email,
		DisplayName: "Conn User",
		AccountType: domain.AccountTypePersonal,
		Status:      domain.UserStatusActive,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	users.put(u)

	return u
}

func TestConnectionService_SendInvite(t *testing.T) {
	t.Parallel()

	t.Run("happy path creates pending edge", func(t *testing.T) {
		t.Parallel()

		users := newFakeUserStore()
		requester := seedConnUser(t, users, "req@example.com")
		addressee := seedConnUser(t, users, "addr@example.com")
		conns := &fakeConnectionStore{}
		svc := service.NewConnectionService(users, conns)

		got, err := svc.SendInvite(context.Background(), requester.ID, addressee.ID)
		require.NoError(t, err)
		require.NotNil(t, got)
		assert.Equal(t, requester.ID, got.RequesterID)
		assert.Equal(t, addressee.ID, got.AddresseeID)
		assert.Equal(t, domain.ConnectionStatusPending, got.Status)
		assert.NotEqual(t, uuid.Nil, got.ID)

		require.NotNil(t, conns.created, "Create must have been called")
		assert.Equal(t, domain.ConnectionStatusPending, conns.created.Status)
	})

	t.Run("self-invite is rejected with ErrValidation (no DB hit)", func(t *testing.T) {
		t.Parallel()

		users := newFakeUserStore()
		me := seedConnUser(t, users, "me@example.com")
		conns := &fakeConnectionStore{}
		svc := service.NewConnectionService(users, conns)

		_, err := svc.SendInvite(context.Background(), me.ID, me.ID)
		require.ErrorIs(t, err, domain.ErrValidation)
		assert.Nil(t, conns.created, "self-invite must short-circuit before Create")
	})

	t.Run("nonexistent addressee returns ErrNotFound", func(t *testing.T) {
		t.Parallel()

		users := newFakeUserStore()
		requester := seedConnUser(t, users, "req2@example.com")
		conns := &fakeConnectionStore{}
		svc := service.NewConnectionService(users, conns)

		_, err := svc.SendInvite(context.Background(), requester.ID, uuid.New())
		require.ErrorIs(t, err, domain.ErrNotFound)
		assert.Nil(t, conns.created, "missing addressee must short-circuit before Create")
	})

	t.Run("duplicate live edge surfaces ErrConnectionExists", func(t *testing.T) {
		t.Parallel()

		users := newFakeUserStore()
		requester := seedConnUser(t, users, "req3@example.com")
		addressee := seedConnUser(t, users, "addr3@example.com")
		conns := &fakeConnectionStore{createErr: domain.ErrConnectionExists}
		svc := service.NewConnectionService(users, conns)

		_, err := svc.SendInvite(context.Background(), requester.ID, addressee.ID)
		require.ErrorIs(t, err, domain.ErrConnectionExists)
	})

	t.Run("addressee lookup backend error is wrapped (not ErrNotFound)", func(t *testing.T) {
		t.Parallel()

		users := newFakeUserStore()
		requester := seedConnUser(t, users, "req4@example.com")
		users.getByIDErr = errInjected
		conns := &fakeConnectionStore{}
		svc := service.NewConnectionService(users, conns)

		_, err := svc.SendInvite(context.Background(), requester.ID, uuid.New())
		require.Error(t, err)
		assert.NotErrorIs(t, err, domain.ErrNotFound, "a generic backend error must not masquerade as 404")
		assert.Nil(t, conns.created)
	})
}

func TestConnectionService_Accept(t *testing.T) {
	t.Parallel()

	t.Run("passes caller id as the addressee guard", func(t *testing.T) {
		t.Parallel()

		conns := &fakeConnectionStore{}
		svc := service.NewConnectionService(newFakeUserStore(), conns)

		id := uuid.New()
		caller := uuid.New()
		require.NoError(t, svc.Accept(context.Background(), id, caller))
		assert.Equal(t, id, conns.acceptedID)
		assert.Equal(t, caller, conns.acceptedBy, "caller id MUST be the SQL-guard addressee (IDOR-safe)")
	})

	t.Run("wrong addressee / unknown id surfaces ErrConnectionNotFound", func(t *testing.T) {
		t.Parallel()

		conns := &fakeConnectionStore{acceptErr: domain.ErrConnectionNotFound}
		svc := service.NewConnectionService(newFakeUserStore(), conns)

		err := svc.Accept(context.Background(), uuid.New(), uuid.New())
		require.ErrorIs(t, err, domain.ErrConnectionNotFound)
	})

	t.Run("already-resolved surfaces ErrConnectionNotPending", func(t *testing.T) {
		t.Parallel()

		conns := &fakeConnectionStore{acceptErr: domain.ErrConnectionNotPending}
		svc := service.NewConnectionService(newFakeUserStore(), conns)

		err := svc.Accept(context.Background(), uuid.New(), uuid.New())
		require.ErrorIs(t, err, domain.ErrConnectionNotPending)
	})
}

func TestConnectionService_Decline(t *testing.T) {
	t.Parallel()

	t.Run("passes caller id as the addressee guard", func(t *testing.T) {
		t.Parallel()

		conns := &fakeConnectionStore{}
		svc := service.NewConnectionService(newFakeUserStore(), conns)

		id := uuid.New()
		caller := uuid.New()
		require.NoError(t, svc.Decline(context.Background(), id, caller))
		assert.Equal(t, id, conns.acceptedID)
		assert.Equal(t, caller, conns.acceptedBy)
	})

	t.Run("already-resolved surfaces ErrConnectionNotPending", func(t *testing.T) {
		t.Parallel()

		conns := &fakeConnectionStore{declineErr: domain.ErrConnectionNotPending}
		svc := service.NewConnectionService(newFakeUserStore(), conns)

		err := svc.Decline(context.Background(), uuid.New(), uuid.New())
		require.ErrorIs(t, err, domain.ErrConnectionNotPending)
	})
}

func TestConnectionService_Lists(t *testing.T) {
	t.Parallel()

	t.Run("ListAccepted passes through carrier rows", func(t *testing.T) {
		t.Parallel()

		conns := &fakeConnectionStore{
			accepted: []store.ConnectionWithUser{{ID: uuid.New(), OtherUserID: uuid.New(), DisplayName: "A"}},
		}
		svc := service.NewConnectionService(newFakeUserStore(), conns)

		got, err := svc.ListAccepted(context.Background(), uuid.New())
		require.NoError(t, err)
		require.Len(t, got, 1)
		assert.Equal(t, "A", got[0].DisplayName)
	})

	t.Run("ListPending returns incoming and outgoing splits", func(t *testing.T) {
		t.Parallel()

		conns := &fakeConnectionStore{
			incoming: []store.ConnectionWithUser{{ID: uuid.New(), DisplayName: "in"}},
			outgoing: []store.ConnectionWithUser{{ID: uuid.New(), DisplayName: "out1"}, {ID: uuid.New(), DisplayName: "out2"}},
		}
		svc := service.NewConnectionService(newFakeUserStore(), conns)

		incoming, outgoing, err := svc.ListPending(context.Background(), uuid.New())
		require.NoError(t, err)
		require.Len(t, incoming, 1)
		require.Len(t, outgoing, 2)
		assert.Equal(t, "in", incoming[0].DisplayName)
	})

	t.Run("list backend error propagates", func(t *testing.T) {
		t.Parallel()

		conns := &fakeConnectionStore{listErr: errInjected}
		svc := service.NewConnectionService(newFakeUserStore(), conns)

		_, err := svc.ListAccepted(context.Background(), uuid.New())
		require.ErrorIs(t, err, errInjected)
	})
}
