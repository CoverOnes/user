package service_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/CoverOnes/user/internal/domain"
	"github.com/CoverOnes/user/internal/service"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// seedCompanyOwner inserts a live COMPANY user linked to companyID via company_id.
func seedCompanyOwner(t *testing.T, users *fakeUserStore, email string, companyID uuid.UUID) *domain.User {
	t.Helper()

	now := time.Now().UTC()
	cid := companyID
	u := &domain.User{
		ID:          uuid.New(),
		Email:       email,
		DisplayName: "Owner",
		AccountType: domain.AccountTypeCompany,
		Status:      domain.UserStatusActive,
		KYCTier:     2,
		CompanyID:   &cid,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	users.put(u)

	return u
}

// newCompanyFixture wires a CompanyService over fakes with a single company owned by
// a freshly-seeded owner user. Returns the service, the company store fake, the
// owner, and the company.
func newCompanyFixture(t *testing.T) (*service.CompanyService, *fakeCompanyStore, *fakeUserStore, *domain.User, *domain.Company) {
	t.Helper()

	users := newFakeUserStore()
	companies := newFakeCompanyStore()

	companyID := uuid.New()
	owner := seedCompanyOwner(t, users, "owner@example.com", companyID)

	now := time.Now().UTC()
	regNo := "REG-123"
	company := &domain.Company{
		ID:             companyID,
		Name:           "Acme",
		RegistrationNo: &regNo,
		OwnerUserID:    owner.ID,
		Status:         domain.CompanyStatusActive,
		CreatedAt:      now,
		UpdatedAt:      now,
	}
	companies.put(company)

	svc := service.NewCompanyService(companies, users)

	return svc, companies, users, owner, company
}

func TestCompanyService_GetMyCompany(t *testing.T) {
	t.Parallel()

	t.Run("owner resolves their own company", func(t *testing.T) {
		t.Parallel()

		svc, _, _, owner, company := newCompanyFixture(t)

		got, err := svc.GetMyCompany(context.Background(), owner.ID)
		require.NoError(t, err)
		assert.Equal(t, company.ID, got.ID)
		require.NotNil(t, got.RegistrationNo)
		assert.Equal(t, "REG-123", *got.RegistrationNo)
	})

	t.Run("caller with no company_id returns ErrCompanyNotFound", func(t *testing.T) {
		t.Parallel()

		svc, _, users, _, _ := newCompanyFixture(t)
		// A PERSONAL user with no company_id.
		lone := &domain.User{
			ID:          uuid.New(),
			Email:       "lone@example.com",
			DisplayName: "Lone",
			AccountType: domain.AccountTypePersonal,
			Status:      domain.UserStatusActive,
		}
		users.put(lone)

		_, err := svc.GetMyCompany(context.Background(), lone.ID)
		require.ErrorIs(t, err, domain.ErrCompanyNotFound)
	})

	t.Run("unknown caller surfaces the user lookup error", func(t *testing.T) {
		t.Parallel()

		svc, _, _, _, _ := newCompanyFixture(t)

		_, err := svc.GetMyCompany(context.Background(), uuid.New())
		require.Error(t, err)
		// The user lookup ErrNotFound is wrapped (→ USER_NOT_FOUND at the handler).
		require.ErrorIs(t, err, domain.ErrNotFound)
	})
}

func TestCompanyService_GetByID(t *testing.T) {
	t.Parallel()

	t.Run("existing company is returned", func(t *testing.T) {
		t.Parallel()

		svc, _, _, _, company := newCompanyFixture(t)

		got, err := svc.GetByID(context.Background(), company.ID)
		require.NoError(t, err)
		assert.Equal(t, company.ID, got.ID)
	})

	t.Run("unknown id is normalized to ErrCompanyNotFound", func(t *testing.T) {
		t.Parallel()

		svc, _, _, _, _ := newCompanyFixture(t)

		_, err := svc.GetByID(context.Background(), uuid.New())
		require.ErrorIs(t, err, domain.ErrCompanyNotFound, "store ErrNotFound must be normalized to ErrCompanyNotFound")
	})
}

func TestCompanyService_UpdateMyCompany_OwnerGate(t *testing.T) {
	t.Parallel()

	t.Run("owner can update", func(t *testing.T) {
		t.Parallel()

		svc, _, _, owner, _ := newCompanyFixture(t)

		got, err := svc.UpdateMyCompany(context.Background(), &service.UpdateCompanyInput{
			CallerID: owner.ID,
			Name:     "Acme Renamed",
		})
		require.NoError(t, err)
		assert.Equal(t, "Acme Renamed", got.Name)
	})

	t.Run("non-owner member is rejected with ErrNotCompanyOwner (403)", func(t *testing.T) {
		t.Parallel()

		svc, companies, users, _, company := newCompanyFixture(t)
		// A second user belonging to the SAME company but who is NOT the owner.
		member := seedCompanyOwner(t, users, "member@example.com", company.ID)

		got, err := svc.UpdateMyCompany(context.Background(), &service.UpdateCompanyInput{
			CallerID: member.ID,
			Name:     "Hijacked Name",
		})
		require.ErrorIs(t, err, domain.ErrNotCompanyOwner)
		assert.Nil(t, got)
		// The company name must be unchanged (the update must short-circuit on the gate).
		stored, err := companies.GetByID(context.Background(), company.ID)
		require.NoError(t, err)
		assert.Equal(t, "Acme", stored.Name, "a non-owner must not mutate the company")
	})

	t.Run("caller with no company returns ErrCompanyNotFound", func(t *testing.T) {
		t.Parallel()

		svc, _, users, _, _ := newCompanyFixture(t)
		lone := &domain.User{
			ID:          uuid.New(),
			Email:       "lone-upd@example.com",
			DisplayName: "Lone",
			AccountType: domain.AccountTypePersonal,
			Status:      domain.UserStatusActive,
		}
		users.put(lone)

		_, err := svc.UpdateMyCompany(context.Background(), &service.UpdateCompanyInput{CallerID: lone.ID, Name: "X"})
		require.ErrorIs(t, err, domain.ErrCompanyNotFound)
	})

	t.Run("handle conflict surfaces ErrHandleTaken (409)", func(t *testing.T) {
		t.Parallel()

		svc, companies, users, owner, _ := newCompanyFixture(t)
		// A second company already holding the handle we will try to take.
		otherID := uuid.New()
		otherOwner := seedCompanyOwner(t, users, "other-owner@example.com", otherID)
		taken := "taken_handle"
		companies.put(&domain.Company{
			ID:          otherID,
			Name:        "Other",
			OwnerUserID: otherOwner.ID,
			Status:      domain.CompanyStatusActive,
			Handle:      &taken,
		})

		conflict := "TAKEN_HANDLE" // case-variant must still collide
		_, err := svc.UpdateMyCompany(context.Background(), &service.UpdateCompanyInput{
			CallerID: owner.ID,
			Name:     "Acme",
			Handle:   &conflict,
		})
		require.ErrorIs(t, err, domain.ErrHandleTaken)
	})
}

func TestCompanyService_UpdateMyCompany_Validation(t *testing.T) {
	t.Parallel()

	overLong := func(n int) *string { s := strings.Repeat("a", n); return &s }
	futureYear := func() *int16 { y := int16(time.Now().UTC().Year() + 1); return &y }
	tooOldYear := func() *int16 { y := int16(1799); return &y }
	controlChar := func() *string { s := "bad\x00name"; return &s }
	badHandle := func() *string { s := "BAD HANDLE!"; return &s }
	badURL := func() *string { s := "ftp://evil.example.com/x"; return &s }

	cases := []struct {
		name  string
		mutIn func(in *service.UpdateCompanyInput)
	}{
		{"empty name", func(in *service.UpdateCompanyInput) { in.Name = "   " }},
		{"name too long", func(in *service.UpdateCompanyInput) { in.Name = strings.Repeat("a", 201) }},
		{"name with control char", func(in *service.UpdateCompanyInput) { in.Name = "bad\x00name" }},
		{"tagline too long", func(in *service.UpdateCompanyInput) { in.Tagline = overLong(121) }},
		{"about too long", func(in *service.UpdateCompanyInput) { in.About = overLong(2001) }},
		{"location too long", func(in *service.UpdateCompanyInput) { in.Location = overLong(101) }},
		{"industry too long", func(in *service.UpdateCompanyInput) { in.Industry = overLong(61) }},
		{"companySize too long", func(in *service.UpdateCompanyInput) { in.CompanySize = overLong(31) }},
		{"about control char", func(in *service.UpdateCompanyInput) { in.About = controlChar() }},
		{"founded year future", func(in *service.UpdateCompanyInput) { in.FoundedYear = futureYear() }},
		{"founded year too old", func(in *service.UpdateCompanyInput) { in.FoundedYear = tooOldYear() }},
		{"bad handle format", func(in *service.UpdateCompanyInput) { in.Handle = badHandle() }},
		{"reserved handle", func(in *service.UpdateCompanyInput) { h := "admin"; in.Handle = &h }},
		{"website bad scheme", func(in *service.UpdateCompanyInput) { in.Website = badURL() }},
		{"logoUrl bad scheme", func(in *service.UpdateCompanyInput) { in.LogoURL = badURL() }},
		{"coverUrl bad scheme", func(in *service.UpdateCompanyInput) { in.CoverURL = badURL() }},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			svc, _, _, owner, _ := newCompanyFixture(t)

			in := &service.UpdateCompanyInput{CallerID: owner.ID, Name: "Valid Name"}
			tc.mutIn(in)

			_, err := svc.UpdateMyCompany(context.Background(), in)
			require.ErrorIs(t, err, domain.ErrValidation, "case %q must wrap ErrValidation", tc.name)
		})
	}

	t.Run("valid full payload succeeds and normalizes handle to lowercase", func(t *testing.T) {
		t.Parallel()

		svc, _, _, owner, _ := newCompanyFixture(t)

		handle := "Acme_CO"
		founded := int16(2010)
		website := "https://acme.example.com"
		got, err := svc.UpdateMyCompany(context.Background(), &service.UpdateCompanyInput{
			CallerID:    owner.ID,
			Name:        "Acme Inc",
			Handle:      &handle,
			FoundedYear: &founded,
			Website:     &website,
		})
		require.NoError(t, err)
		require.NotNil(t, got.Handle)
		assert.Equal(t, "acme_co", *got.Handle, "handle must be lowercased")
		require.NotNil(t, got.FoundedYear)
		assert.Equal(t, int16(2010), *got.FoundedYear)
	})
}

func TestCompanyService_ListMembers(t *testing.T) {
	t.Parallel()

	t.Run("passes through carrier rows from the store", func(t *testing.T) {
		t.Parallel()

		svc, companies, _, _, company := newCompanyFixture(t)
		companies.members[company.ID] = nil // explicit empty

		got, err := svc.ListMembers(context.Background(), company.ID)
		require.NoError(t, err)
		assert.Empty(t, got)
	})

	t.Run("store error propagates", func(t *testing.T) {
		t.Parallel()

		svc, companies, _, _, company := newCompanyFixture(t)
		companies.listMembersErr = errInjected

		_, err := svc.ListMembers(context.Background(), company.ID)
		require.ErrorIs(t, err, errInjected)
	})
}
