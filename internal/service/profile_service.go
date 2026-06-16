package service

import (
	"context"
	"fmt"
	"net/netip"
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
	// M-2: reject control chars / null bytes / ANSI escapes in stored free-text
	// (backend-security §5.4). displayName is rendered in web UI, CLI listings and
	// logs by consumers; untrusted control chars enable stored-XSS, log-injection
	// and terminal-hijack downstream.
	if err := rejectControlChars("displayName", name); err != nil {
		return nil, err
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

	// M-2: reject control chars / null bytes / ANSI escapes (backend-security §5.4).
	if err := rejectControlChars(field, v); err != nil {
		return nil, err
	}

	return &v, nil
}

// rejectControlChars enforces that a stored free-text field contains no characters
// that are unsafe to push to downstream consumers (web UI / CLI listings / logs):
// null bytes, C0 control chars (< 0x20) other than TAB, the DEL char (0x7f), and
// the ANSI escape introducer (0x1b). This is the backend-security §5.4 sanitization
// applied to every stored profile free-text field (displayName, headline, bio,
// location). It does NOT alter the value — it rejects with domain.ErrValidation so
// the client sees a clear 400 rather than silently mangled data. Newline (\n),
// carriage return (\r) and the null byte are all < 0x20 and thus covered here.
func rejectControlChars(field, v string) error {
	for _, r := range v {
		switch {
		case r == '\t':
			// Tab is the single allowed C0 control char.
			continue
		case r == 0x1b:
			// ANSI escape introducer — terminal-hijack vector.
			return fmt.Errorf("%w: %s contains control characters", domain.ErrValidation, field)
		case r < 0x20 || r == 0x7f:
			// C0 controls (incl. \x00, \r, \n) and DEL.
			return fmt.Errorf("%w: %s contains control characters", domain.ErrValidation, field)
		}
	}

	return nil
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
//
// S-1 (defense-in-depth, backend-security adversarial-input): when the host is an
// IP LITERAL, reject any private / loopback / link-local / unspecified address so a
// stored URL can never point at a cloud metadata endpoint (169.254.169.254), an
// internal RFC1918 host (10.x/172.16-31.x/192.168.x), or [::1]. No server-side fetch
// of these URLs exists today (no live SSRF), but hardening at write time prevents a
// future fetcher from being weaponised by already-stored data. Hostname hosts (not IP
// literals) are intentionally NOT resolved here — DNS-rebinding defense belongs at
// fetch time, which does not exist in this service.
//
// The dev http-localhost exemption (127.0.0.1 / ::1) is applied BEFORE the IP-literal
// rejection so loopback dev origins remain usable.
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

	host := u.Hostname()

	// Restrict http to localhost only. These loopback hosts are the ONLY exemption
	// from the IP-literal rejection below (they are explicitly an allowed dev origin).
	if u.Scheme == "http" {
		if host != "localhost" && host != "127.0.0.1" && host != "::1" {
			return "", fmt.Errorf("http avatarUrl is only allowed for localhost; use https for remote hosts")
		}

		return raw, nil
	}

	// https path: if the host is an IP literal, reject internal/metadata ranges.
	if addr, perr := netip.ParseAddr(host); perr == nil {
		if addr.IsPrivate() || addr.IsLoopback() || addr.IsLinkLocalUnicast() ||
			addr.IsLinkLocalMulticast() || addr.IsUnspecified() {
			return "", fmt.Errorf("avatarUrl must not point at a private, loopback, or link-local address")
		}
	}

	return raw, nil
}
