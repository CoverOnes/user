package postgres_test

import (
	"context"
	"testing"
	"time"

	"github.com/CoverOnes/user/internal/domain"
	"github.com/CoverOnes/user/internal/store/postgres"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newSavedItem builds a pending bookmark for the given owner/target with an explicit
// created_at so ORDER BY created_at DESC is deterministic across rows in a test.
func newSavedItem(userID uuid.UUID, itemType string, itemID uuid.UUID, createdAt time.Time) *domain.SavedItem {
	return &domain.SavedItem{
		ID:        uuid.New(),
		UserID:    userID,
		ItemType:  itemType,
		ItemID:    itemID,
		CreatedAt: createdAt,
	}
}

func TestSavedItemStore_Integration(t *testing.T) {
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
	ss := postgres.NewSavedItemStore(pool)

	t.Run("create and list job refs newest-first", func(t *testing.T) {
		owner := seedConnUser(t, ctx, us, "owner-jobs@saved.test", "OwnerJobs")

		now := time.Now().UTC()
		older := newSavedItem(owner.ID, domain.SavedItemTypeJob, uuid.New(), now.Add(-2*time.Hour))
		newer := newSavedItem(owner.ID, domain.SavedItemTypeJob, uuid.New(), now)

		require.NoError(t, ss.Create(ctx, older))
		require.NoError(t, ss.Create(ctx, newer))

		refs, err := ss.ListJobRefs(ctx, owner.ID)
		require.NoError(t, err)
		require.Len(t, refs, 2)
		// Newest-saved-first ordering.
		assert.Equal(t, newer.ItemID, refs[0].ItemID, "newest bookmark must come first")
		assert.Equal(t, older.ItemID, refs[1].ItemID)
		assert.Equal(t, domain.SavedItemTypeJob, refs[0].ItemType)
	})

	t.Run("create and list companies with PII-safe JOIN projection", func(t *testing.T) {
		owner := seedConnUser(t, ctx, us, "owner-co@saved.test", "OwnerCo")
		companyOwner := seedConnUser(t, ctx, us, "co-owner@saved.test", "CoOwner")
		company := seedCompany(t, ctx, cs, companyOwner.ID, "AcmeSaved")

		require.NoError(t, ss.Create(ctx, newSavedItem(owner.ID, domain.SavedItemTypeCompany, company.ID, time.Now().UTC())))

		rows, err := ss.ListCompaniesForUser(ctx, owner.ID)
		require.NoError(t, err)
		require.Len(t, rows, 1)

		card := rows[0]
		assert.Equal(t, company.ID, card.CompanyID)
		assert.Equal(t, "AcmeSaved", card.Name)
		assert.NotEqual(t, uuid.Nil, card.SavedID, "savedId must be populated for unsave + React key")

		// PII-leak guard: the carrier has NO field that can hold registration_no /
		// owner_user_id / status. seedCompany populated registration_no = "REG-AcmeSaved";
		// assert it cannot surface through any projected string field.
		projected := []string{
			card.Name,
			derefOr(card.Handle), derefOr(card.Tagline), derefOr(card.Location),
			derefOr(card.Industry), derefOr(card.CompanySize), derefOr(card.LogoURL),
		}
		for _, s := range projected {
			assert.NotContains(t, s, "REG-AcmeSaved", "no projected field may contain the company registration_no (high-sensitivity)")
			assert.NotContains(t, s, companyOwner.ID.String(), "no projected field may contain owner_user_id")
		}
	})

	t.Run("companies list excludes the OTHER user's bookmarks (identity-scoped)", func(t *testing.T) {
		me := seedConnUser(t, ctx, us, "me-scope@saved.test", "MeScope")
		other := seedConnUser(t, ctx, us, "other-scope@saved.test", "OtherScope")
		coOwner := seedConnUser(t, ctx, us, "co-scope@saved.test", "CoScope")
		company := seedCompany(t, ctx, cs, coOwner.ID, "ScopeCo")

		require.NoError(t, ss.Create(ctx, newSavedItem(other.ID, domain.SavedItemTypeCompany, company.ID, time.Now().UTC())))

		rows, err := ss.ListCompaniesForUser(ctx, me.ID)
		require.NoError(t, err)
		assert.Empty(t, rows, "a user must not see another user's bookmarks")
	})

	t.Run("duplicate live bookmark returns ErrSavedItemExists", func(t *testing.T) {
		owner := seedConnUser(t, ctx, us, "owner-dup@saved.test", "OwnerDup")
		itemID := uuid.New()

		require.NoError(t, ss.Create(ctx, newSavedItem(owner.ID, domain.SavedItemTypeJob, itemID, time.Now().UTC())))

		// Same (user, type, id) triple → unique index 23505.
		err := ss.Create(ctx, newSavedItem(owner.ID, domain.SavedItemTypeJob, itemID, time.Now().UTC()))
		require.ErrorIs(t, err, domain.ErrSavedItemExists)
	})

	t.Run("same item id under different types is allowed (generic table)", func(t *testing.T) {
		owner := seedConnUser(t, ctx, us, "owner-multitype@saved.test", "OwnerMT")
		itemID := uuid.New()

		require.NoError(t, ss.Create(ctx, newSavedItem(owner.ID, domain.SavedItemTypeJob, itemID, time.Now().UTC())))
		// Same id but item_type='company' is a DIFFERENT triple → no conflict.
		require.NoError(t, ss.Create(ctx, newSavedItem(owner.ID, domain.SavedItemTypeCompany, itemID, time.Now().UTC())),
			"the same item_id under a different item_type must not collide")
	})

	t.Run("delete existing bookmark returns removed=true and clears it", func(t *testing.T) {
		owner := seedConnUser(t, ctx, us, "owner-del@saved.test", "OwnerDel")
		itemID := uuid.New()
		require.NoError(t, ss.Create(ctx, newSavedItem(owner.ID, domain.SavedItemTypeJob, itemID, time.Now().UTC())))

		removed, err := ss.DeleteByUserAndItem(ctx, owner.ID, domain.SavedItemTypeJob, itemID)
		require.NoError(t, err)
		assert.True(t, removed, "deleting a present bookmark must report removed=true")

		// Gone from the list.
		refs, err := ss.ListJobRefs(ctx, owner.ID)
		require.NoError(t, err)
		assert.Empty(t, refs)

		// Re-save after hard-delete must succeed (the unique row was removed).
		require.NoError(t, ss.Create(ctx, newSavedItem(owner.ID, domain.SavedItemTypeJob, itemID, time.Now().UTC())),
			"a re-save after unsave must succeed (hard delete removed the unique row)")
	})

	t.Run("delete absent bookmark is idempotent (removed=false, no error)", func(t *testing.T) {
		owner := seedConnUser(t, ctx, us, "owner-idem@saved.test", "OwnerIdem")

		removed, err := ss.DeleteByUserAndItem(ctx, owner.ID, domain.SavedItemTypeCompany, uuid.New())
		require.NoError(t, err, "double-unsave must not error (toggle UX)")
		assert.False(t, removed, "deleting an absent bookmark must report removed=false")
	})

	t.Run("delete is identity-scoped: cannot remove another user's bookmark", func(t *testing.T) {
		me := seedConnUser(t, ctx, us, "me-delscope@saved.test", "MeDelScope")
		other := seedConnUser(t, ctx, us, "other-delscope@saved.test", "OtherDelScope")
		itemID := uuid.New()
		require.NoError(t, ss.Create(ctx, newSavedItem(other.ID, domain.SavedItemTypeJob, itemID, time.Now().UTC())))

		// Me trying to unsave Other's bookmark hits nothing (user_id guard).
		removed, err := ss.DeleteByUserAndItem(ctx, me.ID, domain.SavedItemTypeJob, itemID)
		require.NoError(t, err)
		assert.False(t, removed, "a user must not be able to delete another user's bookmark")

		// Other's bookmark is untouched.
		refs, err := ss.ListJobRefs(ctx, other.ID)
		require.NoError(t, err)
		require.Len(t, refs, 1)
	})

	t.Run("gone company is skipped in the saved-companies list (resolve-on-read)", func(t *testing.T) {
		owner := seedConnUser(t, ctx, us, "owner-gone@saved.test", "OwnerGone")
		coOwner := seedConnUser(t, ctx, us, "co-gone@saved.test", "CoGone")
		live := seedCompany(t, ctx, cs, coOwner.ID, "LiveCo")
		gone := seedCompany(t, ctx, cs, coOwner.ID, "GoneCo")

		require.NoError(t, ss.Create(ctx, newSavedItem(owner.ID, domain.SavedItemTypeCompany, live.ID, time.Now().UTC())))
		require.NoError(t, ss.Create(ctx, newSavedItem(owner.ID, domain.SavedItemTypeCompany, gone.ID, time.Now().UTC())))

		// Sanity: both visible before delete.
		before, err := ss.ListCompaniesForUser(ctx, owner.ID)
		require.NoError(t, err)
		require.Len(t, before, 2)

		// Hard-delete the company row (no FK, no cascade — the saved_items row stays).
		_, err = pool.Exec(ctx, "DELETE FROM companies WHERE id = $1", gone.ID)
		require.NoError(t, err)

		after, err := ss.ListCompaniesForUser(ctx, owner.ID)
		require.NoError(t, err)
		require.Len(t, after, 1, "a saved company whose row is gone must be skipped by the JOIN")
		assert.Equal(t, live.ID, after[0].CompanyID)
	})

	t.Run("empty list returns no rows and no error", func(t *testing.T) {
		owner := seedConnUser(t, ctx, us, "owner-empty@saved.test", "OwnerEmpty")

		jobs, err := ss.ListJobRefs(ctx, owner.ID)
		require.NoError(t, err)
		assert.Empty(t, jobs)

		companies, err := ss.ListCompaniesForUser(ctx, owner.ID)
		require.NoError(t, err)
		assert.Empty(t, companies)
	})

	t.Run("job refs list excludes company bookmarks (type filter)", func(t *testing.T) {
		owner := seedConnUser(t, ctx, us, "owner-typefilter@saved.test", "OwnerTF")
		coOwner := seedConnUser(t, ctx, us, "co-typefilter@saved.test", "CoTF")
		company := seedCompany(t, ctx, cs, coOwner.ID, "TypeFilterCo")

		require.NoError(t, ss.Create(ctx, newSavedItem(owner.ID, domain.SavedItemTypeJob, uuid.New(), time.Now().UTC())))
		require.NoError(t, ss.Create(ctx, newSavedItem(owner.ID, domain.SavedItemTypeCompany, company.ID, time.Now().UTC())))

		jobs, err := ss.ListJobRefs(ctx, owner.ID)
		require.NoError(t, err)
		require.Len(t, jobs, 1, "job list must contain only job bookmarks")
		assert.Equal(t, domain.SavedItemTypeJob, jobs[0].ItemType)
	})

	t.Run("CountByUserAndType is scoped per (user, item_type)", func(t *testing.T) {
		userA := seedConnUser(t, ctx, us, "count-a@saved.test", "CountA")
		userB := seedConnUser(t, ctx, us, "count-b@saved.test", "CountB")

		// Save N=3 distinct job bookmarks for user A.
		const n = 3
		for i := 0; i < n; i++ {
			require.NoError(t, ss.Create(ctx, newSavedItem(userA.ID, domain.SavedItemTypeJob, uuid.New(), time.Now().UTC())))
		}

		// (A, job) sees exactly the 3 saved jobs.
		gotAJob, err := ss.CountByUserAndType(ctx, userA.ID, domain.SavedItemTypeJob)
		require.NoError(t, err)
		assert.Equal(t, n, gotAJob, "count must equal the number of A's job bookmarks")

		// (A, company) is a DIFFERENT item_type → not counted.
		gotACompany, err := ss.CountByUserAndType(ctx, userA.ID, domain.SavedItemTypeCompany)
		require.NoError(t, err)
		assert.Equal(t, 0, gotACompany, "A's job bookmarks must not count toward the company type")

		// (B, job) is a DIFFERENT user → not counted (identity-scoped).
		gotBJob, err := ss.CountByUserAndType(ctx, userB.ID, domain.SavedItemTypeJob)
		require.NoError(t, err)
		assert.Equal(t, 0, gotBJob, "A's job bookmarks must not count toward another user")
	})
}
