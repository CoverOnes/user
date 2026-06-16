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

func strptr(s string) *string { return &s }

// seedProfileUser inserts a basic user for profile tests.
func seedProfileUser(t *testing.T, users *fakeUserStore) *domain.User {
	t.Helper()

	now := time.Now().UTC()
	u := &domain.User{
		ID:          uuid.New(),
		Email:       "profile@example.com",
		DisplayName: "Original",
		AccountType: domain.AccountTypePersonal,
		Status:      domain.UserStatusActive,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	users.put(u)

	return u
}

func TestProfileService_GetByID(t *testing.T) {
	t.Parallel()

	t.Run("happy path", func(t *testing.T) {
		t.Parallel()

		users := newFakeUserStore()
		u := seedProfileUser(t, users)
		svc := service.NewProfileService(users)

		got, err := svc.GetByID(context.Background(), u.ID)
		require.NoError(t, err)
		assert.Equal(t, u.ID, got.ID)
	})

	t.Run("not found", func(t *testing.T) {
		t.Parallel()

		svc := service.NewProfileService(newFakeUserStore())
		_, err := svc.GetByID(context.Background(), uuid.New())
		assert.ErrorIs(t, err, domain.ErrNotFound)
	})

	t.Run("store error propagates", func(t *testing.T) {
		t.Parallel()

		users := newFakeUserStore()
		users.getByIDErr = errInjected
		svc := service.NewProfileService(users)

		_, err := svc.GetByID(context.Background(), uuid.New())
		assert.ErrorIs(t, err, errInjected)
	})
}

func TestProfileService_UpdateProfile(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		displayName string
		avatarURL   *string
		setup       func(u *fakeUserStore) uuid.UUID
		wantErr     error
		// wantAvatar asserts the stored avatar after a successful update (nil = ignore).
		wantAvatar *string
	}{
		{
			name:        "happy path with https avatar",
			displayName: "New Name",
			avatarURL:   strptr("https://cdn.example.com/a.png"),
			wantAvatar:  strptr("https://cdn.example.com/a.png"),
		},
		{
			name:        "happy path nil avatar leaves it unset",
			displayName: "No Avatar",
			avatarURL:   nil,
			wantAvatar:  nil,
		},
		{
			name:        "blank avatar string is treated as no avatar",
			displayName: "Blank Avatar",
			avatarURL:   strptr("   "),
			wantAvatar:  nil,
		},
		{
			name:        "http localhost avatar allowed (dev)",
			displayName: "Local",
			avatarURL:   strptr("http://localhost:8080/a.png"),
			wantAvatar:  strptr("http://localhost:8080/a.png"),
		},
		{
			name:        "empty display name rejected as validation error",
			displayName: "   ",
			wantErr:     domain.ErrValidation,
		},
		{
			name:        "over-long display name rejected",
			displayName: strings.Repeat("x", 81),
			wantErr:     domain.ErrValidation,
		},
		{
			name:        "http non-localhost avatar rejected",
			displayName: "Bad Scheme",
			avatarURL:   strptr("http://evil.example.com/a.png"),
			wantErr:     domain.ErrValidation,
		},
		{
			name:        "file scheme avatar rejected",
			displayName: "File Scheme",
			avatarURL:   strptr("file:///etc/passwd"),
			wantErr:     domain.ErrValidation,
		},
		{
			name:        "javascript scheme avatar rejected",
			displayName: "JS Scheme",
			avatarURL:   strptr("javascript:alert(1)"),
			wantErr:     domain.ErrValidation,
		},
		{
			name:        "https without host rejected",
			displayName: "No Host",
			avatarURL:   strptr("https://"),
			wantErr:     domain.ErrValidation,
		},
		{
			name:        "store update error propagates",
			displayName: "Store Fail",
			setup: func(u *fakeUserStore) uuid.UUID {
				usr := seedProfileUser(t, u)
				u.updateProfileErr = errInjected

				return usr.ID
			},
			wantErr: errInjected,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			users := newFakeUserStore()

			var userID uuid.UUID
			if tc.setup != nil {
				userID = tc.setup(users)
			} else {
				userID = seedProfileUser(t, users).ID
			}

			svc := service.NewProfileService(users)

			got, err := svc.UpdateProfile(context.Background(), &service.UpdateProfileInput{
				UserID:      userID,
				DisplayName: tc.displayName,
				AvatarURL:   tc.avatarURL,
			})

			if tc.wantErr != nil {
				require.Error(t, err)
				assert.ErrorIs(t, err, tc.wantErr)
				assert.Nil(t, got)

				return
			}

			require.NoError(t, err)
			require.NotNil(t, got)
			assert.Equal(t, strings.TrimSpace(tc.displayName), got.DisplayName)

			if tc.wantAvatar == nil {
				assert.Nil(t, got.AvatarURL)
			} else {
				require.NotNil(t, got.AvatarURL)
				assert.Equal(t, *tc.wantAvatar, *got.AvatarURL)
			}
		})
	}
}

// TestProfileService_UpdateProfile_PublicFields exercises the new public-profile
// fields added in P4 (handle normalization + reserved-word blocklist, headline /
// bio / location length bounds, coverUrl scheme allowlist, clear-on-blank).
func TestProfileService_UpdateProfile_PublicFields(t *testing.T) {
	t.Parallel()

	const validName = "Profile User"

	tests := []struct {
		name     string
		in       service.UpdateProfileInput
		wantErr  error
		assertOK func(t *testing.T, got *domain.User)
	}{
		{
			name: "happy path: all public fields set + lowercased handle",
			in: service.UpdateProfileInput{
				DisplayName: validName,
				Handle:      strptr("Profile_Handle_01"),
				Headline:    strptr("  Senior Engineer  "),
				Bio:         strptr("About me"),
				Location:    strptr("Taipei"),
				CoverURL:    strptr("https://cdn.example.com/cover.png"),
			},
			assertOK: func(t *testing.T, got *domain.User) {
				t.Helper()
				require.NotNil(t, got.Handle)
				assert.Equal(t, "profile_handle_01", *got.Handle, "handle must be lowercased")
				require.NotNil(t, got.Headline)
				assert.Equal(t, "Senior Engineer", *got.Headline, "headline must be trimmed")
				require.NotNil(t, got.Bio)
				assert.Equal(t, "About me", *got.Bio)
				require.NotNil(t, got.Location)
				assert.Equal(t, "Taipei", *got.Location)
				require.NotNil(t, got.CoverURL)
				assert.Equal(t, "https://cdn.example.com/cover.png", *got.CoverURL)
			},
		},
		{
			name: "nil public fields clear the columns (full replace)",
			in: service.UpdateProfileInput{
				DisplayName: validName,
			},
			assertOK: func(t *testing.T, got *domain.User) {
				t.Helper()
				assert.Nil(t, got.Handle)
				assert.Nil(t, got.Headline)
				assert.Nil(t, got.Bio)
				assert.Nil(t, got.Location)
				assert.Nil(t, got.CoverURL)
			},
		},
		{
			name: "blank handle clears it",
			in: service.UpdateProfileInput{
				DisplayName: validName,
				Handle:      strptr("   "),
			},
			assertOK: func(t *testing.T, got *domain.User) {
				t.Helper()
				assert.Nil(t, got.Handle)
			},
		},
		{
			name:    "handle too short rejected",
			in:      service.UpdateProfileInput{DisplayName: validName, Handle: strptr("ab")},
			wantErr: domain.ErrValidation,
		},
		{
			name:    "handle too long rejected",
			in:      service.UpdateProfileInput{DisplayName: validName, Handle: strptr(strings.Repeat("a", 31))},
			wantErr: domain.ErrValidation,
		},
		{
			name:    "handle with illegal chars rejected",
			in:      service.UpdateProfileInput{DisplayName: validName, Handle: strptr("bad-handle!")},
			wantErr: domain.ErrValidation,
		},
		{
			name:    "handle with space rejected",
			in:      service.UpdateProfileInput{DisplayName: validName, Handle: strptr("has space")},
			wantErr: domain.ErrValidation,
		},
		{
			name:    "reserved handle 'admin' rejected",
			in:      service.UpdateProfileInput{DisplayName: validName, Handle: strptr("admin")},
			wantErr: domain.ErrValidation,
		},
		{
			name:    "reserved handle 'ADMIN' (case-insensitive) rejected",
			in:      service.UpdateProfileInput{DisplayName: validName, Handle: strptr("ADMIN")},
			wantErr: domain.ErrValidation,
		},
		{
			name:    "over-long headline rejected",
			in:      service.UpdateProfileInput{DisplayName: validName, Headline: strptr(strings.Repeat("h", 121))},
			wantErr: domain.ErrValidation,
		},
		{
			name:    "over-long bio rejected",
			in:      service.UpdateProfileInput{DisplayName: validName, Bio: strptr(strings.Repeat("b", 2001))},
			wantErr: domain.ErrValidation,
		},
		{
			name:    "over-long location rejected",
			in:      service.UpdateProfileInput{DisplayName: validName, Location: strptr(strings.Repeat("l", 101))},
			wantErr: domain.ErrValidation,
		},
		{
			name:    "coverUrl file scheme rejected (SSRF)",
			in:      service.UpdateProfileInput{DisplayName: validName, CoverURL: strptr("file:///etc/passwd")},
			wantErr: domain.ErrValidation,
		},
		{
			name:    "coverUrl http non-localhost rejected",
			in:      service.UpdateProfileInput{DisplayName: validName, CoverURL: strptr("http://evil.example.com/c.png")},
			wantErr: domain.ErrValidation,
		},
		// M-2: control-char / null-byte / ANSI rejection across stored free-text fields.
		{
			name:    "M-2 displayName with null byte rejected",
			in:      service.UpdateProfileInput{DisplayName: "Eve\x00il"},
			wantErr: domain.ErrValidation,
		},
		{
			name:    "M-2 headline with control char rejected",
			in:      service.UpdateProfileInput{DisplayName: validName, Headline: strptr("Senior\x07Engineer")},
			wantErr: domain.ErrValidation,
		},
		{
			name:    "M-2 bio with newline rejected",
			in:      service.UpdateProfileInput{DisplayName: validName, Bio: strptr("line one\nline two")},
			wantErr: domain.ErrValidation,
		},
		{
			name:    "M-2 bio with carriage return rejected",
			in:      service.UpdateProfileInput{DisplayName: validName, Bio: strptr("a\rb")},
			wantErr: domain.ErrValidation,
		},
		{
			name:    "M-2 location with ANSI escape sequence rejected",
			in:      service.UpdateProfileInput{DisplayName: validName, Location: strptr("Taipei\x1b[31m")},
			wantErr: domain.ErrValidation,
		},
		{
			name:    "M-2 location with DEL char rejected",
			in:      service.UpdateProfileInput{DisplayName: validName, Location: strptr("Tai\x7fpei")},
			wantErr: domain.ErrValidation,
		},
		{
			name: "M-2 tab inside bio is allowed",
			in: service.UpdateProfileInput{
				DisplayName: validName,
				Bio:         strptr("col1\tcol2"),
			},
			assertOK: func(t *testing.T, got *domain.User) {
				t.Helper()
				require.NotNil(t, got.Bio)
				assert.Equal(t, "col1\tcol2", *got.Bio)
			},
		},
		// S-1: validateAvatarURL/coverUrl reject IP-literal internal/metadata hosts.
		{
			name:    "S-1 coverUrl cloud metadata IP rejected",
			in:      service.UpdateProfileInput{DisplayName: validName, CoverURL: strptr("https://169.254.169.254/latest/meta-data")},
			wantErr: domain.ErrValidation,
		},
		{
			name:    "S-1 coverUrl private RFC1918 IP rejected",
			in:      service.UpdateProfileInput{DisplayName: validName, CoverURL: strptr("https://10.0.0.1/x")},
			wantErr: domain.ErrValidation,
		},
		{
			name:    "S-1 avatarUrl IPv6 loopback literal rejected",
			in:      service.UpdateProfileInput{DisplayName: validName, AvatarURL: strptr("https://[::1]/x")},
			wantErr: domain.ErrValidation,
		},
		{
			name:    "S-1 avatarUrl unspecified IP rejected",
			in:      service.UpdateProfileInput{DisplayName: validName, AvatarURL: strptr("https://0.0.0.0/x")},
			wantErr: domain.ErrValidation,
		},
		{
			name: "S-1 coverUrl public hostname allowed",
			in: service.UpdateProfileInput{
				DisplayName: validName,
				CoverURL:    strptr("https://cdn.example.com/x.png"),
			},
			assertOK: func(t *testing.T, got *domain.User) {
				t.Helper()
				require.NotNil(t, got.CoverURL)
				assert.Equal(t, "https://cdn.example.com/x.png", *got.CoverURL)
			},
		},
		{
			name: "S-1 avatarUrl public IP literal allowed",
			in: service.UpdateProfileInput{
				DisplayName: validName,
				AvatarURL:   strptr("https://8.8.8.8/x.png"),
			},
			assertOK: func(t *testing.T, got *domain.User) {
				t.Helper()
				require.NotNil(t, got.AvatarURL)
				assert.Equal(t, "https://8.8.8.8/x.png", *got.AvatarURL)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			users := newFakeUserStore()
			u := seedProfileUser(t, users)
			svc := service.NewProfileService(users)

			in := tc.in
			in.UserID = u.ID

			got, err := svc.UpdateProfile(context.Background(), &in)

			if tc.wantErr != nil {
				require.Error(t, err)
				assert.ErrorIs(t, err, tc.wantErr)
				assert.Nil(t, got)

				return
			}

			require.NoError(t, err)
			require.NotNil(t, got)

			if tc.assertOK != nil {
				tc.assertOK(t, got)
			}
		})
	}
}

// TestProfileService_UpdateProfile_HandleTaken verifies the store-level
// ErrHandleTaken (partial-unique violation) propagates through the service.
func TestProfileService_UpdateProfile_HandleTaken(t *testing.T) {
	t.Parallel()

	users := newFakeUserStore()
	svc := service.NewProfileService(users)

	// Seed two users; user A claims "taken".
	a := seedProfileUser(t, users)
	now := time.Now().UTC()
	b := &domain.User{
		ID:          uuid.New(),
		Email:       "second@example.com",
		DisplayName: "Second",
		AccountType: domain.AccountTypePersonal,
		Status:      domain.UserStatusActive,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	users.put(b)

	_, err := svc.UpdateProfile(context.Background(), &service.UpdateProfileInput{
		UserID:      a.ID,
		DisplayName: "A",
		Handle:      strptr("taken"),
	})
	require.NoError(t, err)

	// User B tries to claim the same handle (different case) → conflict.
	_, err = svc.UpdateProfile(context.Background(), &service.UpdateProfileInput{
		UserID:      b.ID,
		DisplayName: "B",
		Handle:      strptr("TAKEN"),
	})
	assert.ErrorIs(t, err, domain.ErrHandleTaken)
}
