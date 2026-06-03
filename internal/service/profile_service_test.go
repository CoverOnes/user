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

			got, err := svc.UpdateProfile(context.Background(), service.UpdateProfileInput{
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
