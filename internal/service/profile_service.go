package service

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/CoverOnes/user/internal/domain"
	"github.com/CoverOnes/user/internal/store"
	"github.com/google/uuid"
)

// allowedAvatarSchemes is the allowlist for avatar URL schemes.
// http is permitted for localhost/dev origins only; all others must be https.
var allowedAvatarSchemes = map[string]bool{
	"https": true,
	"http":  true, // restricted to localhost in validateAvatarURL
}

// Public-profile field bounds. Length is enforced HERE (service layer), never via
// DB CHECK constraints (platform rule §5.2). Bounds match the frozen API contract.
const (
	handleMinLen   = 3
	handleMaxLen   = 30
	headlineMaxLen = 120
	bioMaxLen      = 2000
	locationMaxLen = 100
)

// handleRegexp is the allowlist for handles: lowercase ASCII letters, digits and
// underscore only. Handles are lowercased BEFORE this check, so an upper-case
// input is normalized rather than rejected outright.
var handleRegexp = regexp.MustCompile(`^[a-z0-9_]+$`)

// reservedHandles are handles that collide with routing / system paths and must
// never be claimed by a user. Compared against the lowercased handle.
var reservedHandles = map[string]bool{
	"me":       true,
	"admin":    true,
	"api":      true,
	"profile":  true,
	"settings": true,
}

// ProfileService handles profile-related business logic.
type ProfileService struct {
	users store.UserStore
}

// NewProfileService creates a ProfileService with the given user store.
func NewProfileService(users store.UserStore) *ProfileService {
	return &ProfileService{users: users}
}

// GetByID fetches the current user profile.
func (s *ProfileService) GetByID(ctx context.Context, id uuid.UUID) (*domain.User, error) {
	return s.users.GetByID(ctx, id)
}

// UpdateProfileInput carries the raw update payload. All *string fields are
// optional from the client's perspective; nil leaves the column cleared (the PUT
// contract is a full replace of editable fields). Validation + normalization
// happens in UpdateProfile.
type UpdateProfileInput struct {
	UserID      uuid.UUID
	DisplayName string
	Handle      *string
	Headline    *string
	Bio         *string
	Location    *string
	AvatarURL   *string
	CoverURL    *string
}

// UpdateProfile validates + normalizes the payload and applies a full-replace
// profile update, returning the refreshed row. All validation failures wrap
// domain.ErrValidation (→ HTTP 400). A handle uniqueness conflict surfaces from
// the store as domain.ErrHandleTaken (→ HTTP 409).
func (s *ProfileService) UpdateProfile(ctx context.Context, in *UpdateProfileInput) (*domain.User, error) {
	name := strings.TrimSpace(in.DisplayName)
	if len([]rune(name)) < 1 || len([]rune(name)) > 80 {
		// F7: use ErrValidation for input validation, not ErrInvalidCredentials (which maps to 401).
		return nil, fmt.Errorf("%w: displayName must be 1-80 characters", domain.ErrValidation)
	}

	handle, err := normalizeHandle(in.Handle)
	if err != nil {
		return nil, err
	}

	headline, err := validateOptionalText("headline", in.Headline, headlineMaxLen)
	if err != nil {
		return nil, err
	}

	bio, err := validateOptionalText("bio", in.Bio, bioMaxLen)
	if err != nil {
		return nil, err
	}

	location, err := validateOptionalText("location", in.Location, locationMaxLen)
	if err != nil {
		return nil, err
	}

	avatarURL, err := validateOptionalImageURL("avatarUrl", in.AvatarURL)
	if err != nil {
		return nil, err
	}

	coverURL, err := validateOptionalImageURL("coverUrl", in.CoverURL)
	if err != nil {
		return nil, err
	}

	update := store.ProfileUpdate{
		DisplayName: name,
		Handle:      handle,
		Headline:    headline,
		Bio:         bio,
		Location:    location,
		AvatarURL:   avatarURL,
		CoverURL:    coverURL,
	}

	if err := s.users.UpdateProfile(ctx, in.UserID, update); err != nil {
		return nil, err
	}

	return s.users.GetByID(ctx, in.UserID)
}

// normalizeHandle lowercases, validates, and reserved-word-checks a handle.
// A nil input or a blank (whitespace-only) input returns (nil, nil) — the handle
// is cleared. A non-blank handle must be 3-30 chars matching ^[a-z0-9_]+$ and not
// be a reserved word. Validation failures wrap domain.ErrValidation.
func normalizeHandle(raw *string) (*string, error) {
	if raw == nil {
		// nil/blank means "no handle / clear the column" — not an error.
		return nil, nil
	}

	h := strings.ToLower(strings.TrimSpace(*raw))
	if h == "" {
		return nil, nil
	}

	if n := len([]rune(h)); n < handleMinLen || n > handleMaxLen {
		return nil, fmt.Errorf("%w: handle must be %d-%d characters", domain.ErrValidation, handleMinLen, handleMaxLen)
	}

	if !handleRegexp.MatchString(h) {
		return nil, fmt.Errorf("%w: handle may only contain lowercase letters, digits and underscore", domain.ErrValidation)
	}

	if reservedHandles[h] {
		return nil, fmt.Errorf("%w: handle %q is reserved", domain.ErrValidation, h)
	}

	return &h, nil
}

// validateOptionalText trims an optional free-text field and enforces a rune-count
// max. A nil or blank value returns (nil, nil) — the column is cleared. Over-length
// wraps domain.ErrValidation.
func validateOptionalText(field string, raw *string, maxLen int) (*string, error) {
	if raw == nil {
		// nil/blank means "clear the column" — not an error.
		return nil, nil
	}

	v := strings.TrimSpace(*raw)
	if v == "" {
		return nil, nil
	}

	if len([]rune(v)) > maxLen {
		return nil, fmt.Errorf("%w: %s must be at most %d characters", domain.ErrValidation, field, maxLen)
	}

	return &v, nil
}

// validateOptionalImageURL trims an optional image URL and validates it against the
// shared scheme allowlist (https always; http localhost-only). A nil or blank value
// returns (nil, nil) — the column is cleared. Invalid scheme/host wraps
// domain.ErrValidation. Used for both avatarUrl and coverUrl (shared SSRF defense).
func validateOptionalImageURL(field string, raw *string) (*string, error) {
	if raw == nil {
		// nil/blank means "clear the column" — not an error.
		return nil, nil
	}

	v := strings.TrimSpace(*raw)
	if v == "" {
		return nil, nil
	}

	validated, err := validateAvatarURL(v)
	if err != nil {
		return nil, fmt.Errorf("%w: %s %s", domain.ErrValidation, field, err.Error())
	}

	return &validated, nil
}

// validateAvatarURL enforces scheme whitelist (F2):
//   - https is always allowed
//   - http is allowed only for localhost / 127.0.0.1 (dev use)
//   - file://, data:, ftp:, and any other scheme are rejected
//   - host must be non-empty
func validateAvatarURL(raw string) (string, error) {
	u, err := url.ParseRequestURI(raw)
	if err != nil {
		return "", fmt.Errorf("invalid URL")
	}

	if !allowedAvatarSchemes[u.Scheme] {
		return "", fmt.Errorf("avatarUrl scheme %q not allowed; only https (or http for localhost) is permitted", u.Scheme)
	}

	if u.Host == "" {
		return "", fmt.Errorf("avatarUrl must have a host")
	}

	// Restrict http to localhost only.
	if u.Scheme == "http" {
		host := u.Hostname()
		if host != "localhost" && host != "127.0.0.1" && host != "::1" {
			return "", fmt.Errorf("http avatarUrl is only allowed for localhost; use https for remote hosts")
		}
	}

	return raw, nil
}
