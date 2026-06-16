package service_test

import (
	"context"
	"testing"

	"github.com/CoverOnes/user/internal/domain"
	"github.com/CoverOnes/user/internal/service"
	"github.com/CoverOnes/user/internal/store"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeSavedItemStore is an in-memory SavedItemStore for SavedService unit tests, with
// per-method error injection and a record of the last Create / Delete so a test can
// assert the constructed bookmark + delete keys. The JOIN projection + 23505 unique
// semantics live in SQL and are covered by the Postgres integration test; this fake
// only needs enough behavior to drive the service-layer branches.
type fakeSavedItemStore struct {
	createErr error
	deleteErr error
	listErr   error
	countErr  error

	created *domain.SavedItem

	deletedUser uuid.UUID
	deletedType string
	deletedID   uuid.UUID
	deleteRet   bool

	// countRet is what CountByUserAndType returns; countCalled / counted* record the
	// last call so a test can assert the cap check ran with the caller's id + type.
	countRet    int
	countCalled bool
	countedUser uuid.UUID
	countedType string

	jobRefs   []domain.SavedItem
	companies []store.SavedCompanyRow
}

func (f *fakeSavedItemStore) Create(_ context.Context, s *domain.SavedItem) error {
	if f.createErr != nil {
		return f.createErr
	}

	cp := *s
	f.created = &cp

	return nil
}

func (f *fakeSavedItemStore) DeleteByUserAndItem(_ context.Context, userID uuid.UUID, itemType string, itemID uuid.UUID) (bool, error) {
	if f.deleteErr != nil {
		return false, f.deleteErr
	}

	f.deletedUser = userID
	f.deletedType = itemType
	f.deletedID = itemID

	return f.deleteRet, nil
}

func (f *fakeSavedItemStore) CountByUserAndType(_ context.Context, userID uuid.UUID, itemType string) (int, error) {
	if f.countErr != nil {
		return 0, f.countErr
	}

	f.countCalled = true
	f.countedUser = userID
	f.countedType = itemType

	return f.countRet, nil
}

func (f *fakeSavedItemStore) ListJobRefs(_ context.Context, _ uuid.UUID) ([]domain.SavedItem, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}

	return f.jobRefs, nil
}

func (f *fakeSavedItemStore) ListCompaniesForUser(_ context.Context, _ uuid.UUID) ([]store.SavedCompanyRow, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}

	return f.companies, nil
}

// seedSavedCompany inserts a live company into the shared fakeCompanyStore so the
// company-target existence check in Save resolves.
func seedSavedCompany(companies *fakeCompanyStore) *domain.Company {
	c := &domain.Company{
		ID:          uuid.New(),
		Name:        "Saved Co",
		OwnerUserID: uuid.New(),
		Status:      domain.CompanyStatusActive,
	}
	companies.put(c)

	return c
}

func TestSavedService_Save(t *testing.T) {
	t.Parallel()

	t.Run("save company verifies the target exists and creates a bookmark", func(t *testing.T) {
		t.Parallel()

		companies := newFakeCompanyStore()
		company := seedSavedCompany(companies)
		saved := &fakeSavedItemStore{}
		svc := service.NewSavedService(companies, saved)

		caller := uuid.New()
		got, err := svc.Save(context.Background(), caller, domain.SavedItemTypeCompany, company.ID)
		require.NoError(t, err)
		require.NotNil(t, got)
		assert.Equal(t, caller, got.UserID, "owner of the bookmark MUST be the caller")
		assert.Equal(t, domain.SavedItemTypeCompany, got.ItemType)
		assert.Equal(t, company.ID, got.ItemID)
		assert.NotEqual(t, uuid.Nil, got.ID)

		require.NotNil(t, saved.created, "Create must have been called")
		assert.Equal(t, company.ID, saved.created.ItemID)
	})

	t.Run("save company with absent target returns ErrSavedTargetNotFound", func(t *testing.T) {
		t.Parallel()

		companies := newFakeCompanyStore()
		saved := &fakeSavedItemStore{}
		svc := service.NewSavedService(companies, saved)

		_, err := svc.Save(context.Background(), uuid.New(), domain.SavedItemTypeCompany, uuid.New())
		require.ErrorIs(t, err, domain.ErrSavedTargetNotFound)
		assert.Nil(t, saved.created, "an absent company target must short-circuit before Create")
	})

	t.Run("save job SKIPS the existence check (delegated marketplace)", func(t *testing.T) {
		t.Parallel()

		companies := newFakeCompanyStore()
		// companies is empty: a job save must NOT touch it / must NOT 404.
		saved := &fakeSavedItemStore{}
		svc := service.NewSavedService(companies, saved)

		caller := uuid.New()
		jobID := uuid.New()
		got, err := svc.Save(context.Background(), caller, domain.SavedItemTypeJob, jobID)
		require.NoError(t, err, "a job target is never existence-checked (delegated DB)")
		require.NotNil(t, got)
		assert.Equal(t, domain.SavedItemTypeJob, got.ItemType)
		assert.Equal(t, jobID, got.ItemID)
		require.NotNil(t, saved.created)
	})

	t.Run("save with invalid item type returns ErrValidation (no DB hit)", func(t *testing.T) {
		t.Parallel()

		companies := newFakeCompanyStore()
		saved := &fakeSavedItemStore{}
		svc := service.NewSavedService(companies, saved)

		_, err := svc.Save(context.Background(), uuid.New(), "person", uuid.New())
		require.ErrorIs(t, err, domain.ErrValidation)
		assert.Nil(t, saved.created, "an invalid type must short-circuit before Create")
	})

	t.Run("duplicate bookmark surfaces ErrSavedItemExists", func(t *testing.T) {
		t.Parallel()

		companies := newFakeCompanyStore()
		saved := &fakeSavedItemStore{createErr: domain.ErrSavedItemExists}
		svc := service.NewSavedService(companies, saved)

		_, err := svc.Save(context.Background(), uuid.New(), domain.SavedItemTypeJob, uuid.New())
		require.ErrorIs(t, err, domain.ErrSavedItemExists)
	})

	t.Run("company-target lookup backend error is wrapped (not 404)", func(t *testing.T) {
		t.Parallel()

		companies := newFakeCompanyStore()
		companies.getByIDErr = errInjected
		saved := &fakeSavedItemStore{}
		svc := service.NewSavedService(companies, saved)

		_, err := svc.Save(context.Background(), uuid.New(), domain.SavedItemTypeCompany, uuid.New())
		require.Error(t, err)
		assert.NotErrorIs(t, err, domain.ErrSavedTargetNotFound, "a generic backend error must not masquerade as 404")
		assert.Nil(t, saved.created)
	})

	t.Run("save at the per-user-per-type ceiling is rejected with ErrValidation (no Create)", func(t *testing.T) {
		t.Parallel()

		companies := newFakeCompanyStore()
		// count == maxSavedPerUserPerType (1000): the cap is inclusive (n >= max), so
		// the very next save must be rejected and MUST NOT reach Create.
		saved := &fakeSavedItemStore{countRet: 1000}
		svc := service.NewSavedService(companies, saved)

		caller := uuid.New()
		_, err := svc.Save(context.Background(), caller, domain.SavedItemTypeJob, uuid.New())
		require.ErrorIs(t, err, domain.ErrValidation, "hitting the cap must map to a 400 VALIDATION_ERROR")
		assert.Nil(t, saved.created, "a save at the cap must short-circuit before Create")
		assert.True(t, saved.countCalled, "the cap check must have run")
		assert.Equal(t, caller, saved.countedUser, "the cap must be scoped to the caller id")
		assert.Equal(t, domain.SavedItemTypeJob, saved.countedType, "the cap must be scoped to the item_type")
	})

	t.Run("save just below the ceiling proceeds to Create", func(t *testing.T) {
		t.Parallel()

		companies := newFakeCompanyStore()
		// count == 999 (max-1): still under the cap, so the save proceeds.
		saved := &fakeSavedItemStore{countRet: 999}
		svc := service.NewSavedService(companies, saved)

		caller := uuid.New()
		jobID := uuid.New()
		got, err := svc.Save(context.Background(), caller, domain.SavedItemTypeJob, jobID)
		require.NoError(t, err, "a save below the cap must succeed")
		require.NotNil(t, got)
		assert.Equal(t, jobID, got.ItemID)
		require.NotNil(t, saved.created, "Create must have been called when under the cap")
		assert.Equal(t, jobID, saved.created.ItemID)
	})

	t.Run("cap-count backend error is wrapped and short-circuits before Create", func(t *testing.T) {
		t.Parallel()

		companies := newFakeCompanyStore()
		saved := &fakeSavedItemStore{countErr: errInjected}
		svc := service.NewSavedService(companies, saved)

		_, err := svc.Save(context.Background(), uuid.New(), domain.SavedItemTypeJob, uuid.New())
		require.ErrorIs(t, err, errInjected, "a count backend error must propagate")
		assert.NotErrorIs(t, err, domain.ErrValidation, "a backend error must not masquerade as a cap rejection")
		assert.Nil(t, saved.created, "a count error must short-circuit before Create")
	})
}

func TestSavedService_Unsave(t *testing.T) {
	t.Parallel()

	t.Run("unsave passes caller id + keys to the identity-scoped delete", func(t *testing.T) {
		t.Parallel()

		saved := &fakeSavedItemStore{deleteRet: true}
		svc := service.NewSavedService(newFakeCompanyStore(), saved)

		caller := uuid.New()
		itemID := uuid.New()
		removed, err := svc.Unsave(context.Background(), caller, domain.SavedItemTypeCompany, itemID)
		require.NoError(t, err)
		assert.True(t, removed)
		assert.Equal(t, caller, saved.deletedUser, "delete MUST be scoped to the caller id")
		assert.Equal(t, domain.SavedItemTypeCompany, saved.deletedType)
		assert.Equal(t, itemID, saved.deletedID)
	})

	t.Run("unsave absent bookmark is idempotent (removed=false, no error)", func(t *testing.T) {
		t.Parallel()

		saved := &fakeSavedItemStore{deleteRet: false}
		svc := service.NewSavedService(newFakeCompanyStore(), saved)

		removed, err := svc.Unsave(context.Background(), uuid.New(), domain.SavedItemTypeJob, uuid.New())
		require.NoError(t, err, "double-unsave must not error (toggle UX)")
		assert.False(t, removed)
	})

	t.Run("unsave with invalid item type returns ErrValidation (no DB hit)", func(t *testing.T) {
		t.Parallel()

		saved := &fakeSavedItemStore{}
		svc := service.NewSavedService(newFakeCompanyStore(), saved)

		_, err := svc.Unsave(context.Background(), uuid.New(), "document", uuid.New())
		require.ErrorIs(t, err, domain.ErrValidation)
		assert.Equal(t, uuid.Nil, saved.deletedUser, "an invalid type must short-circuit before the delete")
	})

	t.Run("delete backend error propagates", func(t *testing.T) {
		t.Parallel()

		saved := &fakeSavedItemStore{deleteErr: errInjected}
		svc := service.NewSavedService(newFakeCompanyStore(), saved)

		_, err := svc.Unsave(context.Background(), uuid.New(), domain.SavedItemTypeJob, uuid.New())
		require.ErrorIs(t, err, errInjected)
	})
}

func TestSavedService_Lists(t *testing.T) {
	t.Parallel()

	t.Run("ListJobs passes through bare refs", func(t *testing.T) {
		t.Parallel()

		saved := &fakeSavedItemStore{
			jobRefs: []domain.SavedItem{{ID: uuid.New(), ItemType: domain.SavedItemTypeJob, ItemID: uuid.New()}},
		}
		svc := service.NewSavedService(newFakeCompanyStore(), saved)

		got, err := svc.ListJobs(context.Background(), uuid.New())
		require.NoError(t, err)
		require.Len(t, got, 1)
		assert.Equal(t, domain.SavedItemTypeJob, got[0].ItemType)
	})

	t.Run("ListCompanies passes through carrier rows", func(t *testing.T) {
		t.Parallel()

		saved := &fakeSavedItemStore{
			companies: []store.SavedCompanyRow{{SavedID: uuid.New(), CompanyID: uuid.New(), Name: "Acme"}},
		}
		svc := service.NewSavedService(newFakeCompanyStore(), saved)

		got, err := svc.ListCompanies(context.Background(), uuid.New())
		require.NoError(t, err)
		require.Len(t, got, 1)
		assert.Equal(t, "Acme", got[0].Name)
	})

	t.Run("list backend error propagates", func(t *testing.T) {
		t.Parallel()

		saved := &fakeSavedItemStore{listErr: errInjected}
		svc := service.NewSavedService(newFakeCompanyStore(), saved)

		_, err := svc.ListJobs(context.Background(), uuid.New())
		require.ErrorIs(t, err, errInjected)
	})
}
