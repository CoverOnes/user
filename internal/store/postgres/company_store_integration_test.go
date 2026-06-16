package postgres_test

import (
	"context"
	"testing"
	"time"

	"github.com/CoverOnes/user/internal/domain"
	"github.com/CoverOnes/user/internal/store"
	"github.com/CoverOnes/user/internal/store/postgres"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// seedCompany inserts an ACTIVE company owned by ownerID. registration_no is
// populated so the PII-safe member/public projections can be proven NOT to surface it.
func seedCompany(t *testing.T, ctx context.Context, cs *postgres.CompanyStore, ownerID uuid.UUID, name string) *domain.Company {
	t.Helper()

	now := time.Now().UTC().Truncate(time.Millisecond)
	regNo := "REG-" + name
	c := &domain.Company{
		ID:             uuid.New(),
		Name:           name,
		RegistrationNo: &regNo,
		OwnerUserID:    ownerID,
		Status:         domain.CompanyStatusActive,
		CreatedAt:      now,
		UpdatedAt:      now,
	}
	require.NoError(t, cs.Create(ctx, c))

	return c
}

// memberSeed groups the parameters for seedCompanyMember (keeps the helper signature
// short — lll). createdOffset shifts created_at so ORDER BY created_at ASC is
// deterministic across members.
type memberSeed struct {
	companyID     uuid.UUID
	email         string
	name          string
	createdOffset time.Duration
}

// seedCompanyMember inserts a live user linked to a company via company_id, with
// public-profile + PII columns populated, then stamps created_at deterministically.
func seedCompanyMember(t *testing.T, ctx context.Context, pool *pgxpool.Pool, us *postgres.UserStore, in memberSeed) *domain.User {
	t.Helper()

	now := time.Now().UTC().Add(in.createdOffset).Truncate(time.Millisecond)
	handle := in.name
	headline := "Headline " + in.name
	avatar := "https://cdn.example.com/" + in.name + ".png"
	companyIDCopy := in.companyID
	u := &domain.User{
		ID:            uuid.New(),
		Email:         in.email,
		PasswordHash:  testPH(),
		DisplayName:   in.name,
		Handle:        &handle,
		Headline:      &headline,
		AvatarURL:     &avatar,
		AccountType:   domain.AccountTypeCompany,
		KYCTier:       2,
		CompanyID:     &companyIDCopy,
		Status:        domain.UserStatusActive,
		LegalNameEnc:  []byte("ciphertext-legal-" + in.name),
		NationalIDEnc: []byte("ciphertext-natid-" + in.name),
		CreatedAt:     now,
		UpdatedAt:     now,
	}
	require.NoError(t, us.Create(ctx, u))

	// Create() does not persist a created_at override deterministically across drivers,
	// so stamp the desired created_at explicitly to control ORDER BY.
	_, err := pool.Exec(ctx, "UPDATE users SET created_at = $2 WHERE id = $1", u.ID, now)
	require.NoError(t, err)

	return u
}

func TestCompanyStore_Integration(t *testing.T) {
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
	cs := postgres.NewCompanyStore(pool)

	t.Run("update full-replace then GetByID reflects all profile columns", func(t *testing.T) {
		owner := seedConnUser(t, ctx, us, "owner-update@company.test", "Owner")
		company := seedCompany(t, ctx, cs, owner.ID, "Acme Original")

		handle := "acme_co"
		tagline := "We build things"
		about := "A long company description"
		location := "Taipei"
		website := "https://acme.example.com"
		industry := "Construction"
		size := "11-50"
		founded := int16(1999)
		logo := "https://cdn.example.com/logo.png"
		cover := "https://cdn.example.com/cover.png"

		require.NoError(t, cs.Update(ctx, company.ID, &store.CompanyUpdate{
			Name:        "Acme Updated",
			Handle:      &handle,
			Tagline:     &tagline,
			About:       &about,
			Location:    &location,
			Website:     &website,
			Industry:    &industry,
			CompanySize: &size,
			FoundedYear: &founded,
			LogoURL:     &logo,
			CoverURL:    &cover,
		}))

		got, err := cs.GetByID(ctx, company.ID)
		require.NoError(t, err)
		assert.Equal(t, "Acme Updated", got.Name)
		require.NotNil(t, got.Handle)
		assert.Equal(t, "acme_co", *got.Handle)
		require.NotNil(t, got.FoundedYear)
		assert.Equal(t, int16(1999), *got.FoundedYear)
		require.NotNil(t, got.Website)
		assert.Equal(t, website, *got.Website)
		// owner_user_id + registration_no remain unchanged (Update never touches them).
		assert.Equal(t, owner.ID, got.OwnerUserID)
		require.NotNil(t, got.RegistrationNo)
		assert.Equal(t, "REG-Acme Original", *got.RegistrationNo)
	})

	t.Run("update clears nullable columns when set to nil (full-replace)", func(t *testing.T) {
		owner := seedConnUser(t, ctx, us, "owner-clear@company.test", "OwnerClear")
		company := seedCompany(t, ctx, cs, owner.ID, "Clearable")

		handle := "clearable_co"
		require.NoError(t, cs.Update(ctx, company.ID, &store.CompanyUpdate{Name: "Clearable", Handle: &handle}))

		// A second full-replace with all-nil optionals must clear the previously-set handle.
		require.NoError(t, cs.Update(ctx, company.ID, &store.CompanyUpdate{Name: "Clearable"}))

		got, err := cs.GetByID(ctx, company.ID)
		require.NoError(t, err)
		assert.Nil(t, got.Handle, "nil handle on full-replace must clear the column")
		assert.Nil(t, got.Tagline)
	})

	t.Run("update handle uniqueness violation returns ErrHandleTaken", func(t *testing.T) {
		ownerA := seedConnUser(t, ctx, us, "owner-a-handle@company.test", "OwnerA")
		ownerB := seedConnUser(t, ctx, us, "owner-b-handle@company.test", "OwnerB")
		companyA := seedCompany(t, ctx, cs, ownerA.ID, "CompanyA")
		companyB := seedCompany(t, ctx, cs, ownerB.ID, "CompanyB")

		taken := "shared_handle"
		require.NoError(t, cs.Update(ctx, companyA.ID, &store.CompanyUpdate{Name: "CompanyA", Handle: &taken}))

		// citext: a case-variant of the taken handle must still collide.
		variant := "SHARED_HANDLE"
		err := cs.Update(ctx, companyB.ID, &store.CompanyUpdate{Name: "CompanyB", Handle: &variant})
		require.ErrorIs(t, err, domain.ErrHandleTaken, "duplicate handle (case-insensitive) must surface ErrHandleTaken")
	})

	t.Run("update nonexistent company returns ErrCompanyNotFound", func(t *testing.T) {
		err := cs.Update(ctx, uuid.New(), &store.CompanyUpdate{Name: "Ghost"})
		require.ErrorIs(t, err, domain.ErrCompanyNotFound)
	})

	t.Run("list members PII-safe + isOwner + created_at ASC ordering", func(t *testing.T) {
		owner := seedConnUser(t, ctx, us, "owner-members@company.test", "RosterOwner")
		company := seedCompany(t, ctx, cs, owner.ID, "RosterCo")

		// Link the owner user to the company so they appear in the roster with isOwner=true.
		_, err := pool.Exec(ctx, "UPDATE users SET company_id = $2 WHERE id = $1", owner.ID, company.ID)
		require.NoError(t, err)
		// Stamp the owner earliest so created_at ASC puts the owner first deterministically.
		_, err = pool.Exec(ctx, "UPDATE users SET created_at = $2 WHERE id = $1", owner.ID, time.Now().UTC().Add(-2*time.Hour))
		require.NoError(t, err)

		m1 := seedCompanyMember(t, ctx, pool, us, memberSeed{companyID: company.ID, email: "m1-members@company.test", name: "Member1", createdOffset: -1 * time.Hour})
		m2 := seedCompanyMember(t, ctx, pool, us, memberSeed{companyID: company.ID, email: "m2-members@company.test", name: "Member2", createdOffset: 0})

		members, err := cs.ListMembers(ctx, company.ID)
		require.NoError(t, err)
		require.Len(t, members, 3, "owner + 2 members")

		// Ordering: created_at ASC → owner, m1, m2.
		assert.Equal(t, owner.ID, members[0].UserID)
		assert.True(t, members[0].IsOwner, "the owner row must have isOwner=true")
		assert.Equal(t, m1.ID, members[1].UserID)
		assert.False(t, members[1].IsOwner, "a non-owner member must have isOwner=false")
		assert.Equal(t, m2.ID, members[2].UserID)
		assert.False(t, members[2].IsOwner)

		// PII-safe: the carrier struct has NO field for email/national_id/kyc_tier;
		// defense-in-depth assert the projected display fields don't contain the email.
		for _, mem := range members {
			for _, s := range []string{mem.DisplayName, derefOr(mem.Handle), derefOr(mem.Headline), derefOr(mem.AvatarURL)} {
				assert.NotContains(t, s, "@company.test", "no projected member field may contain an email (PII)")
			}
		}
	})

	t.Run("list members excludes soft-deleted users", func(t *testing.T) {
		owner := seedConnUser(t, ctx, us, "owner-softdel-mem@company.test", "SoftDelOwner")
		company := seedCompany(t, ctx, cs, owner.ID, "SoftDelCo")

		alive := seedCompanyMember(t, ctx, pool, us, memberSeed{companyID: company.ID, email: "alive-mem@company.test", name: "Alive", createdOffset: -1 * time.Hour})
		gone := seedCompanyMember(t, ctx, pool, us, memberSeed{companyID: company.ID, email: "gone-mem@company.test", name: "Gone", createdOffset: 0})

		// Sanity: both present before the soft-delete.
		before, err := cs.ListMembers(ctx, company.ID)
		require.NoError(t, err)
		require.Len(t, before, 2)

		softDeleteUser(t, ctx, pool, gone.ID)

		after, err := cs.ListMembers(ctx, company.ID)
		require.NoError(t, err)
		require.Len(t, after, 1, "a soft-deleted member must be excluded")
		assert.Equal(t, alive.ID, after[0].UserID)
	})

	t.Run("list members for company with no members returns empty (not error)", func(t *testing.T) {
		owner := seedConnUser(t, ctx, us, "owner-empty-mem@company.test", "EmptyOwner")
		company := seedCompany(t, ctx, cs, owner.ID, "EmptyCo")

		// Owner user is NOT linked via company_id, so the roster is empty.
		members, err := cs.ListMembers(ctx, company.ID)
		require.NoError(t, err)
		assert.Empty(t, members, "a company with no linked users yields an empty roster")
	})

	t.Run("list members for unknown company returns empty (no oracle)", func(t *testing.T) {
		members, err := cs.ListMembers(ctx, uuid.New())
		require.NoError(t, err)
		assert.Empty(t, members)
	})
}
