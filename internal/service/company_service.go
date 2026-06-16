package service

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/CoverOnes/user/internal/domain"
	"github.com/CoverOnes/user/internal/store"
	"github.com/google/uuid"
)

// Company public-profile field bounds. Length is enforced HERE (service layer),
// never via DB CHECK constraints (platform rule §5.2). Bounds match the frozen API
// contract (spec §5.2). handle reuses the SAME handleMinLen/handleMaxLen + regexp +
// reserved set as the user profile (profile_service.go) so the validation surface is
// consistent across both verticals.
const (
	companyNameMinLen     = 1
	companyNameMaxLen     = 200
	companyTaglineMaxLen  = 120
	companyAboutMaxLen    = 2000
	companyLocationMaxLen = 100
	companyIndustryMaxLen = 60
	companySizeMaxLen     = 30
	companyFoundedYearMin = 1800
)

// CompanyService holds the business logic for the P4 Company aggregate. Referential
// integrity is enforced in code (no FK, red-line #9): the caller→company link is
// users.company_id and owner-gating is companies.owner_user_id == callerID, both
// validated here rather than by a DB constraint.
type CompanyService struct {
	users     store.UserStore
	companies store.CompanyStore
}

// NewCompanyService creates a CompanyService.
func NewCompanyService(companies store.CompanyStore, users store.UserStore) *CompanyService {
	return &CompanyService{companies: companies, users: users}
}

// GetByID fetches a company by id for the PUBLIC profile endpoint. The store returns
// domain.ErrNotFound for an absent row; it is normalized to domain.ErrCompanyNotFound
// so the handler maps it to the company-specific 404 code (resolved-decision #1).
func (s *CompanyService) GetByID(ctx context.Context, id uuid.UUID) (*domain.Company, error) {
	c, err := s.companies.GetByID(ctx, id)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return nil, domain.ErrCompanyNotFound
		}

		return nil, fmt.Errorf("get company: %w", err)
	}

	return c, nil
}

// ListMembers returns the company's PII-safe team roster (live users WHERE
// company_id, ordered created_at ASC, isOwner derived). An unknown company id yields
// an empty slice (the store treats membership as non-oracular; the public GET company
// endpoint is the canonical existence check).
func (s *CompanyService) ListMembers(ctx context.Context, companyID uuid.UUID) ([]store.CompanyMember, error) {
	return s.companies.ListMembers(ctx, companyID)
}

// GetMyCompany resolves the authenticated caller's company: load the user, follow
// users.company_id, then GetByID. A caller with no company_id (e.g. a PERSONAL
// account) → domain.ErrCompanyNotFound (404). The user lookup itself returning
// ErrNotFound (deleted user) is surfaced as-is → USER_NOT_FOUND.
func (s *CompanyService) GetMyCompany(ctx context.Context, callerID uuid.UUID) (*domain.Company, error) {
	u, err := s.users.GetByID(ctx, callerID)
	if err != nil {
		return nil, fmt.Errorf("get caller: %w", err)
	}

	if u.CompanyID == nil {
		return nil, domain.ErrCompanyNotFound
	}

	return s.GetByID(ctx, *u.CompanyID)
}

// UpdateCompanyInput carries the raw PUT /v1/me/company payload. All optional fields
// are nil-clearable (full-replace contract). Validation + normalization happens in
// UpdateMyCompany. CallerID is the JWT subject (the owner-gate authority) — never a
// body value.
type UpdateCompanyInput struct {
	CallerID    uuid.UUID
	Name        string
	Handle      *string
	Tagline     *string
	About       *string
	Location    *string
	Website     *string
	Industry    *string
	CompanySize *string
	FoundedYear *int16
	LogoURL     *string
	CoverURL    *string
}

// UpdateMyCompany owner-gates + validates + applies a full-replace update to the
// caller's company, returning the refreshed row.
//
// Order of checks:
//  1. Resolve the caller's company (GetMyCompany) — nil company_id → ErrCompanyNotFound.
//  2. OWNER-GATE: company.OwnerUserID != callerID → ErrNotCompanyOwner (403). This is
//     the authorization boundary; a non-owner member can READ via GetMyCompany but
//     cannot mutate.
//  3. Validate + normalize every field (wraps domain.ErrValidation → 400).
//  4. companies.Update — the partial-unique index is the race-safe handle authority
//     (23505 → ErrHandleTaken / 409); we never check-then-update.
func (s *CompanyService) UpdateMyCompany(ctx context.Context, in *UpdateCompanyInput) (*domain.Company, error) {
	company, err := s.GetMyCompany(ctx, in.CallerID)
	if err != nil {
		return nil, err
	}

	if company.OwnerUserID != in.CallerID {
		return nil, domain.ErrNotCompanyOwner
	}

	update, err := s.validateCompanyUpdate(in)
	if err != nil {
		return nil, err
	}

	if err := s.companies.Update(ctx, company.ID, update); err != nil {
		// ErrHandleTaken (23505) and ErrCompanyNotFound (no row) surface as-is.
		return nil, err
	}

	return s.GetByID(ctx, company.ID)
}

// validateCompanyUpdate validates + normalizes the payload into a store.CompanyUpdate.
// Reuses the shared profile_service validators (normalizeHandle, validateOptionalText,
// validateOptionalImageURL, rejectControlChars) so the rules are identical across the
// profile and company verticals. Returns the carrier on success; any failure wraps
// domain.ErrValidation (→ HTTP 400).
//
//nolint:cyclop // straight-line per-field validation: 11 independent non-nested checks; splitting scatters the full-replace field set, obscures the contract.
func (s *CompanyService) validateCompanyUpdate(in *UpdateCompanyInput) (*store.CompanyUpdate, error) {
	name := strings.TrimSpace(in.Name)
	if n := len([]rune(name)); n < companyNameMinLen || n > companyNameMaxLen {
		return nil, fmt.Errorf("%w: name must be %d-%d characters", domain.ErrValidation, companyNameMinLen, companyNameMaxLen)
	}

	if err := rejectControlChars("name", name); err != nil {
		return nil, err
	}

	handle, err := normalizeHandle(in.Handle)
	if err != nil {
		return nil, err
	}

	tagline, err := validateOptionalText("tagline", in.Tagline, companyTaglineMaxLen)
	if err != nil {
		return nil, err
	}

	about, err := validateOptionalText("about", in.About, companyAboutMaxLen)
	if err != nil {
		return nil, err
	}

	location, err := validateOptionalText("location", in.Location, companyLocationMaxLen)
	if err != nil {
		return nil, err
	}

	industry, err := validateOptionalText("industry", in.Industry, companyIndustryMaxLen)
	if err != nil {
		return nil, err
	}

	companySize, err := validateOptionalText("companySize", in.CompanySize, companySizeMaxLen)
	if err != nil {
		return nil, err
	}

	foundedYear, err := validateFoundedYear(in.FoundedYear)
	if err != nil {
		return nil, err
	}

	website, err := validateOptionalImageURL("website", in.Website)
	if err != nil {
		return nil, err
	}

	logoURL, err := validateOptionalImageURL("logoUrl", in.LogoURL)
	if err != nil {
		return nil, err
	}

	coverURL, err := validateOptionalImageURL("coverUrl", in.CoverURL)
	if err != nil {
		return nil, err
	}

	return &store.CompanyUpdate{
		Name:        name,
		Handle:      handle,
		Tagline:     tagline,
		About:       about,
		Location:    location,
		Website:     website,
		Industry:    industry,
		CompanySize: companySize,
		FoundedYear: foundedYear,
		LogoURL:     logoURL,
		CoverURL:    coverURL,
	}, nil
}

// validateFoundedYear bounds-checks an optional founding year against
// [companyFoundedYearMin, currentYear]. A nil value returns (nil, nil) — the column
// is cleared. Out-of-range wraps domain.ErrValidation. The upper bound is the current
// UTC year (computed at call time, not a frozen constant) so a future year is rejected.
func validateFoundedYear(raw *int16) (*int16, error) {
	if raw == nil {
		return nil, nil
	}

	currentYear := int16(time.Now().UTC().Year())
	if *raw < companyFoundedYearMin || *raw > currentYear {
		return nil, fmt.Errorf("%w: foundedYear must be between %d and %d", domain.ErrValidation, companyFoundedYearMin, currentYear)
	}

	return raw, nil
}
