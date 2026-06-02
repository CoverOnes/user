package service

import (
	"context"
	"fmt"
	"net/url"
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

// UpdateProfileInput carries the validated update payload.
type UpdateProfileInput struct {
	UserID      uuid.UUID
	DisplayName string
	AvatarURL   *string
}

// UpdateProfile validates and applies a profile update.
func (s *ProfileService) UpdateProfile(ctx context.Context, in UpdateProfileInput) (*domain.User, error) {
	name := strings.TrimSpace(in.DisplayName)
	if len([]rune(name)) < 1 || len([]rune(name)) > 80 {
		// F7: use ErrValidation for input validation, not ErrInvalidCredentials (which maps to 401).
		return nil, fmt.Errorf("%w: displayName must be 1-80 characters", domain.ErrValidation)
	}

	var avatarURL *string
	if in.AvatarURL != nil {
		trimmed := strings.TrimSpace(*in.AvatarURL)
		if trimmed != "" {
			validated, err := validateAvatarURL(trimmed)
			if err != nil {
				// F7: ErrValidation maps to HTTP 400, not 401.
				return nil, fmt.Errorf("%w: %s", domain.ErrValidation, err.Error())
			}
			avatarURL = &validated
		}
	}

	if err := s.users.UpdateProfile(ctx, in.UserID, name, avatarURL); err != nil {
		return nil, err
	}

	return s.users.GetByID(ctx, in.UserID)
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
