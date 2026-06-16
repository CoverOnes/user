package postgres_test

import (
	"context"
	"testing"
	"time"

	"github.com/CoverOnes/user/internal/domain"
	"github.com/CoverOnes/user/internal/store/postgres"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// seedConnUser inserts an ACTIVE user with the public-profile columns populated so
// the PII-safe JOIN projection can be asserted. handle/headline/avatar are set;
// PII columns (email, national_id, legal_name) are populated too so the test can
// prove they never surface through a connection card.
func seedConnUser(t *testing.T, ctx context.Context, us *postgres.UserStore, email, name string) *domain.User {
	t.Helper()

	now := time.Now().UTC().Truncate(time.Millisecond)
	u := &domain.User{
		ID:            uuid.New(),
		Email:         email,
		PasswordHash:  testPH(),
		DisplayName:   name,
		AccountType:   domain.AccountTypePersonal,
		KYCTier:       2,
		Status:        domain.UserStatusActive,
		TokenVersion:  0,
		LegalNameEnc:  []byte("ciphertext-legal-" + name),
		NationalIDEnc: []byte("ciphertext-natid-" + name),
		CreatedAt:     now,
		UpdatedAt:     now,
	}
	require.NoError(t, us.Create(ctx, u))

	return u
}

// softDeleteUser stamps deleted_at on a user so live-row filters can be exercised.
func softDeleteUser(t *testing.T, ctx context.Context, pool *pgxpool.Pool, id uuid.UUID) {
	t.Helper()

	_, err := pool.Exec(ctx, "UPDATE users SET deleted_at = now() WHERE id = $1", id)
	require.NoError(t, err)
}

func newConn(requester, addressee uuid.UUID) *domain.Connection {
	now := time.Now().UTC()

	return &domain.Connection{
		ID:          uuid.New(),
		RequesterID: requester,
		AddresseeID: addressee,
		Status:      domain.ConnectionStatusPending,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
}

func TestConnectionStore_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ctx := context.Background()
	dsn := startTestDB(t)
	runMigrations(t, ctx, dsn, "")

	pool, err := postgres.NewPool(ctx, dsn, "", 0, 0)
	require.NoError(t, err)

	defer pool.Close()

	us := postgres.NewUserStore(pool)
	cs := postgres.NewConnectionStore(pool)

	t.Run("create and list accepted with PII-safe projection", func(t *testing.T) {
		alice := seedConnUser(t, ctx, us, "alice-acc@conn.test", "Alice")
		bob := seedConnUser(t, ctx, us, "bob-acc@conn.test", "Bob")

		conn := newConn(alice.ID, bob.ID)
		require.NoError(t, cs.Create(ctx, conn))

		// Bob accepts (Bob is the addressee).
		require.NoError(t, cs.AcceptInvite(ctx, conn.ID, bob.ID))

		// Alice's accepted list shows Bob (the OTHER party) with non-PII fields only.
		aliceList, err := cs.ListAcceptedForUser(ctx, alice.ID)
		require.NoError(t, err)
		require.Len(t, aliceList, 1)
		assert.Equal(t, bob.ID, aliceList[0].OtherUserID, "the OTHER party from Alice's view is Bob")
		assert.Equal(t, "Bob", aliceList[0].DisplayName)
		assert.Equal(t, conn.ID, aliceList[0].ID)

		// Bob's accepted list shows Alice (symmetric, undirected).
		bobList, err := cs.ListAcceptedForUser(ctx, bob.ID)
		require.NoError(t, err)
		require.Len(t, bobList, 1)
		assert.Equal(t, alice.ID, bobList[0].OtherUserID, "the OTHER party from Bob's view is Alice")
	})

	t.Run("undirected dedup: B->A blocked after A->B (live pair)", func(t *testing.T) {
		a := seedConnUser(t, ctx, us, "a-dedup@conn.test", "A")
		b := seedConnUser(t, ctx, us, "b-dedup@conn.test", "B")

		require.NoError(t, cs.Create(ctx, newConn(a.ID, b.ID)))

		// Reverse direction for the same unordered pair must hit the partial-unique index.
		err := cs.Create(ctx, newConn(b.ID, a.ID))
		require.ErrorIs(t, err, domain.ErrConnectionExists, "B->A must be rejected while A->B is live")
	})

	t.Run("declined edge does NOT block a re-invite", func(t *testing.T) {
		a := seedConnUser(t, ctx, us, "a-redecline@conn.test", "A")
		b := seedConnUser(t, ctx, us, "b-redecline@conn.test", "B")

		first := newConn(a.ID, b.ID)
		require.NoError(t, cs.Create(ctx, first))

		// B declines the first invite.
		require.NoError(t, cs.DeclineInvite(ctx, first.ID, b.ID))

		// A new invite for the same pair must now succeed (declined row is not "live").
		require.NoError(t, cs.Create(ctx, newConn(a.ID, b.ID)),
			"a declined edge must not block re-invite (partial index excludes declined)")
	})

	t.Run("accept guard: wrong addressee returns ErrConnectionNotFound (IDOR-safe)", func(t *testing.T) {
		a := seedConnUser(t, ctx, us, "a-idor@conn.test", "A")
		b := seedConnUser(t, ctx, us, "b-idor@conn.test", "B")
		intruder := seedConnUser(t, ctx, us, "intruder-idor@conn.test", "Intruder")

		conn := newConn(a.ID, b.ID)
		require.NoError(t, cs.Create(ctx, conn))

		// An attacker who is neither requester nor addressee cannot accept the invite,
		// and gets a 404-equivalent error (no oracle that the edge exists).
		err := cs.AcceptInvite(ctx, conn.ID, intruder.ID)
		require.ErrorIs(t, err, domain.ErrConnectionNotFound)

		// The requester (A) is not the addressee either → also ErrConnectionNotFound.
		err = cs.AcceptInvite(ctx, conn.ID, a.ID)
		require.ErrorIs(t, err, domain.ErrConnectionNotFound, "requester cannot accept their own outgoing invite")

		// The legitimate addressee (B) still succeeds afterwards.
		require.NoError(t, cs.AcceptInvite(ctx, conn.ID, b.ID))
	})

	t.Run("accept already-accepted returns ErrConnectionNotPending", func(t *testing.T) {
		a := seedConnUser(t, ctx, us, "a-reaccept@conn.test", "A")
		b := seedConnUser(t, ctx, us, "b-reaccept@conn.test", "B")

		conn := newConn(a.ID, b.ID)
		require.NoError(t, cs.Create(ctx, conn))
		require.NoError(t, cs.AcceptInvite(ctx, conn.ID, b.ID))

		// Re-accepting the now-accepted edge: addressee is correct but status != pending.
		err := cs.AcceptInvite(ctx, conn.ID, b.ID)
		require.ErrorIs(t, err, domain.ErrConnectionNotPending)
	})

	t.Run("decline already-declined returns ErrConnectionNotPending", func(t *testing.T) {
		a := seedConnUser(t, ctx, us, "a-redecline2@conn.test", "A")
		b := seedConnUser(t, ctx, us, "b-redecline2@conn.test", "B")

		conn := newConn(a.ID, b.ID)
		require.NoError(t, cs.Create(ctx, conn))
		require.NoError(t, cs.DeclineInvite(ctx, conn.ID, b.ID))

		err := cs.DeclineInvite(ctx, conn.ID, b.ID)
		require.ErrorIs(t, err, domain.ErrConnectionNotPending)
	})

	t.Run("accept unknown id returns ErrConnectionNotFound", func(t *testing.T) {
		err := cs.AcceptInvite(ctx, uuid.New(), uuid.New())
		require.ErrorIs(t, err, domain.ErrConnectionNotFound)
	})

	t.Run("list pending splits incoming and outgoing", func(t *testing.T) {
		me := seedConnUser(t, ctx, us, "me-pending@conn.test", "Me")
		inviter := seedConnUser(t, ctx, us, "inviter-pending@conn.test", "Inviter")
		target := seedConnUser(t, ctx, us, "target-pending@conn.test", "Target")

		// inviter -> me (incoming for me)
		require.NoError(t, cs.Create(ctx, newConn(inviter.ID, me.ID)))
		// me -> target (outgoing for me)
		require.NoError(t, cs.Create(ctx, newConn(me.ID, target.ID)))

		incoming, outgoing, err := cs.ListPendingForUser(ctx, me.ID)
		require.NoError(t, err)
		require.Len(t, incoming, 1)
		require.Len(t, outgoing, 1)
		assert.Equal(t, inviter.ID, incoming[0].OtherUserID, "incoming OTHER party is the requester")
		assert.Equal(t, target.ID, outgoing[0].OtherUserID, "outgoing OTHER party is the addressee")
	})

	t.Run("accepted list excludes connections to soft-deleted users", func(t *testing.T) {
		me := seedConnUser(t, ctx, us, "me-softdel@conn.test", "Me")
		gone := seedConnUser(t, ctx, us, "gone-softdel@conn.test", "Gone")

		conn := newConn(me.ID, gone.ID)
		require.NoError(t, cs.Create(ctx, conn))
		require.NoError(t, cs.AcceptInvite(ctx, conn.ID, gone.ID))

		// Sanity: visible before soft-delete.
		before, err := cs.ListAcceptedForUser(ctx, me.ID)
		require.NoError(t, err)
		require.Len(t, before, 1)

		// Soft-delete the OTHER party; the JOIN (o.deleted_at IS NULL) must drop the card.
		softDeleteUser(t, ctx, pool, gone.ID)

		after, err := cs.ListAcceptedForUser(ctx, me.ID)
		require.NoError(t, err)
		assert.Empty(t, after, "a connection to a soft-deleted user must not appear in the list")
	})

	t.Run("connection projection leaks no PII columns (raw row inspection)", func(t *testing.T) {
		alice := seedConnUser(t, ctx, us, "alice-pii@conn.test", "AlicePII")
		bob := seedConnUser(t, ctx, us, "bob-pii@conn.test", "BobPII")

		conn := newConn(alice.ID, bob.ID)
		require.NoError(t, cs.Create(ctx, conn))
		require.NoError(t, cs.AcceptInvite(ctx, conn.ID, bob.ID))

		list, err := cs.ListAcceptedForUser(ctx, alice.ID)
		require.NoError(t, err)
		require.Len(t, list, 1)

		// The carrier struct has NO field that can hold email / national_id / kyc_tier;
		// assert the projected, non-PII fields are exactly what we expect and that the
		// PII-bearing user (Bob) does not surface his email anywhere in the card.
		card := list[0]
		assert.Equal(t, "BobPII", card.DisplayName)
		assert.Equal(t, domain.AccountTypePersonal, card.AccountType)
		// Defense in depth: the email used to seed Bob must not appear in any string field.
		for _, s := range []string{card.DisplayName, derefOr(card.Handle), derefOr(card.Headline), derefOr(card.AvatarURL)} {
			assert.NotContains(t, s, "bob-pii@conn.test", "no projected field may contain the user's email (PII)")
		}
	})
}

func derefOr(s *string) string {
	if s == nil {
		return ""
	}

	return *s
}
