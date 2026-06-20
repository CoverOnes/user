package handler_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/CoverOnes/user/internal/auth/jwt"
	"github.com/CoverOnes/user/internal/domain"
	"github.com/CoverOnes/user/internal/handler"
	"github.com/CoverOnes/user/internal/platform/middleware"
	"github.com/CoverOnes/user/internal/service"
	"github.com/CoverOnes/user/internal/store"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- handler-layer reset fakes ---

// resetUserStore is a minimal in-memory UserStore for password-reset handler tests.
// It implements store.UserStore (all methods needed by the service layer).
type resetUserStore struct {
	users map[uuid.UUID]*domain.User
}

func newResetUserStore() *resetUserStore {
	return &resetUserStore{users: make(map[uuid.UUID]*domain.User)}
}

func (s *resetUserStore) put(u *domain.User) {
	cp := *u
	s.users[u.ID] = &cp
}

func (s *resetUserStore) Create(_ context.Context, u *domain.User) error {
	s.users[u.ID] = u
	return nil
}

func (s *resetUserStore) GetByID(_ context.Context, id uuid.UUID) (*domain.User, error) {
	u, ok := s.users[id]
	if !ok {
		return nil, domain.ErrNotFound
	}
	return u, nil
}

func (s *resetUserStore) GetByEmail(_ context.Context, email string) (*domain.User, error) {
	for _, u := range s.users {
		if u.Email == email {
			return u, nil
		}
	}
	return nil, domain.ErrNotFound
}

func (s *resetUserStore) UpdateProfile(_ context.Context, _ uuid.UUID, _ store.ProfileUpdate) error {
	return nil
}

func (s *resetUserStore) UpdateKYCTier(_ context.Context, _ uuid.UUID, _ int16) error { return nil }

func (s *resetUserStore) BumpTokenVersion(_ context.Context, id uuid.UUID) (int, error) {
	u, ok := s.users[id]
	if !ok {
		return 0, domain.ErrNotFound
	}
	u.TokenVersion++
	return u.TokenVersion, nil
}

func (s *resetUserStore) SetEmailVerified(_ context.Context, id uuid.UUID) error {
	u, ok := s.users[id]
	if !ok {
		return domain.ErrNotFound
	}
	u.EmailVerified = true
	return nil
}

func (s *resetUserStore) SetPendingTOTPSecret(_ context.Context, _ uuid.UUID, _ []byte) error {
	return nil
}

func (s *resetUserStore) EnableMFA(_ context.Context, _ uuid.UUID, _ []byte, _ time.Time) error {
	return nil
}

func (s *resetUserStore) DisableMFA(_ context.Context, _ uuid.UUID) error { return nil }

func (s *resetUserStore) SetMFABackupCodes(_ context.Context, _ uuid.UUID, _ []byte) error {
	return nil
}

func (s *resetUserStore) SetPasswordHash(_ context.Context, id uuid.UUID, hash string) error {
	u, ok := s.users[id]
	if !ok {
		return domain.ErrNotFound
	}
	u.PasswordHash = &hash
	return nil
}

// resetTokenStore is an in-memory PasswordResetTokenStore for handler tests.
type resetTokenStore struct {
	byHash map[string]*domain.PasswordResetToken
}

func newResetTokenStore() *resetTokenStore {
	return &resetTokenStore{byHash: make(map[string]*domain.PasswordResetToken)}
}

func (s *resetTokenStore) Create(_ context.Context, t *domain.PasswordResetToken) error {
	s.byHash[string(t.TokenHash)] = t
	return nil
}

func (s *resetTokenStore) GetByHash(_ context.Context, tokenHash []byte) (*domain.PasswordResetToken, error) {
	t, ok := s.byHash[string(tokenHash)]
	if !ok {
		return nil, domain.ErrInvalidResetToken
	}
	cp := *t
	return &cp, nil
}

func (s *resetTokenStore) MarkUsed(_ context.Context, id uuid.UUID, now time.Time) error {
	for _, t := range s.byHash {
		if t.ID == id {
			if t.UsedAt != nil {
				return domain.ErrInvalidResetToken
			}
			t.UsedAt = &now
			return nil
		}
	}
	return domain.ErrInvalidResetToken
}

func (s *resetTokenStore) InvalidateForUser(_ context.Context, userID uuid.UUID, now time.Time) error {
	for _, t := range s.byHash {
		if t.UserID == userID && t.UsedAt == nil {
			t.UsedAt = &now
		}
	}
	return nil
}

// resetTxRunner executes fn sequentially (no-tx fallback, adequate for unit tests).
type resetTxRunner struct {
	users  store.UserStore
	resets store.PasswordResetTokenStore
}

func (r *resetTxRunner) WithResetTx(
	ctx context.Context,
	fn func(ctx context.Context, users store.UserStore, resets store.PasswordResetTokenStore) error,
) error {
	return fn(ctx, r.users, r.resets)
}

// spyResetMailer captures password-reset send calls.
type spyResetMailer struct{}

func (m *spyResetMailer) SendVerification(_ context.Context, _, _ string) error  { return nil }
func (m *spyResetMailer) SendPasswordReset(_ context.Context, _, _ string) error { return nil }

// noopEncryptorReset satisfies any encryptor interface needed by WithVerification.
type noopEncryptorReset struct{}

func (e *noopEncryptorReset) Encrypt(s string) ([]byte, error) { return []byte(s), nil }
func (e *noopEncryptorReset) Decrypt(b []byte) (string, error) { return string(b), nil }

// buildResetRouter builds a Gin router with the password-reset endpoints wired.
func buildResetRouter(
	t *testing.T,
	userStore *resetUserStore,
	resetStore *resetTokenStore,
) *gin.Engine {
	t.Helper()

	signer, err := jwt.NewEphemeralSigner(10 * time.Minute)
	require.NoError(t, err)

	companyStore := &fakeCompanyStore{}
	rtStore := newFakeRefreshTokenStore()

	authSvc := service.NewAuthService(userStore, companyStore, rtStore, nil, signer, 10*time.Minute, 24)
	authSvc = authSvc.WithVerification(
		newFakeVerificationStoreForHandler(),
		&noopEncryptorReset{},
		&spyResetMailer{},
		nil,
	)

	rtx := &resetTxRunner{users: userStore, resets: resetStore}
	authSvc = authSvc.WithPasswordReset(resetStore, rtx, allowAllHandlerLimiter{})

	r := gin.New()
	r.Use(middleware.Recover())
	r.Use(middleware.RequestID())

	authH := handler.NewAuthHandler(authSvc, signer, "", 24)
	auth := r.Group("/v1/auth")
	auth.POST("/forgot-password", authH.ForgotPassword)
	auth.POST("/reset-password", authH.ResetPassword)

	return r
}

// --- fakes needed by buildResetRouter but defined here to avoid handler_test duplication ---

type allowAllHandlerLimiter struct{}

func (allowAllHandlerLimiter) Allow(_ context.Context, _ string) bool { return true }

// fakeVerificationStoreForHandler satisfies WithVerification (not under test here).
type fakeVerificationStoreForHandler struct{}

func (f *fakeVerificationStoreForHandler) Create(_ context.Context, _ *domain.EmailVerificationToken) error {
	return nil
}

func (f *fakeVerificationStoreForHandler) GetByHash(_ context.Context, _ []byte) (*domain.EmailVerificationToken, error) {
	return nil, domain.ErrInvalidVerificationToken
}

func (f *fakeVerificationStoreForHandler) MarkConsumed(_ context.Context, _ uuid.UUID, _ time.Time) error {
	return domain.ErrInvalidVerificationToken
}

func (f *fakeVerificationStoreForHandler) InvalidateForUser(_ context.Context, _ uuid.UUID, _ time.Time) error {
	return nil
}

func newFakeVerificationStoreForHandler() *fakeVerificationStoreForHandler {
	return &fakeVerificationStoreForHandler{}
}

// --- helpers ---

func postResetJSON(t *testing.T, r http.Handler, path string, body any) *httptest.ResponseRecorder {
	t.Helper()

	b, err := json.Marshal(body)
	require.NoError(t, err)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, path, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	return w
}

// seedHandlerUser inserts an active, email-verified user suitable for reset tests.
func seedHandlerUser(users *resetUserStore, email string) *domain.User {
	hashStr := "$argon2id$v=19$m=65536,t=3,p=2$abc$def"
	now := time.Now().UTC()
	u := &domain.User{
		ID:            uuid.New(),
		Email:         email,
		PasswordHash:  &hashStr,
		DisplayName:   "Reset Test",
		AccountType:   domain.AccountTypePersonal,
		Status:        domain.UserStatusActive,
		EmailVerified: true,
		CreatedAt:     now,
		UpdatedAt:     now,
	}
	users.put(u)
	return u
}

// seedHandlerResetToken stores a reset token (sha256 of rawToken) in the store.
func seedHandlerResetToken(resets *resetTokenStore, userID uuid.UUID, rawToken string, expiresAt time.Time, usedAt *time.Time) {
	sum := sha256.Sum256([]byte(rawToken))
	rt := &domain.PasswordResetToken{
		ID:        uuid.New(),
		UserID:    userID,
		TokenHash: sum[:],
		ExpiresAt: expiresAt,
		UsedAt:    usedAt,
		CreatedAt: time.Now().UTC(),
	}
	_ = resets.Create(context.Background(), rt)
}

// --- Tests ---

// A2: ForgotPassword must always return 202 regardless of whether the email exists.
func TestHandler_ForgotPassword_AlwaysAccepted(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name  string
		email string
		setup func(users *resetUserStore)
	}{
		{
			name:  "unknown email → 202 (no enumeration)",
			email: "ghost@example.com",
			setup: func(_ *resetUserStore) {},
		},
		{
			name:  "unverified user → 202 (no enumeration)",
			email: "unverified@example.com",
			setup: func(users *resetUserStore) {
				u := seedHandlerUser(users, "unverified@example.com")
				users.users[u.ID].EmailVerified = false
				users.users[u.ID].Status = domain.UserStatusPendingVerification
			},
		},
		{
			name:  "suspended user → 202 (no enumeration)",
			email: "suspended@example.com",
			setup: func(users *resetUserStore) {
				u := seedHandlerUser(users, "suspended@example.com")
				users.users[u.ID].Status = domain.UserStatusSuspended
			},
		},
		{
			name:  "eligible user → 202",
			email: "eligible@example.com",
			setup: func(users *resetUserStore) {
				seedHandlerUser(users, "eligible@example.com")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			users := newResetUserStore()
			tc.setup(users)
			resets := newResetTokenStore()
			r := buildResetRouter(t, users, resets)

			w := postResetJSON(t, r, "/v1/auth/forgot-password", map[string]any{
				"email": tc.email,
			})

			// Must always be 202 — no enumeration oracle.
			assert.Equal(t, http.StatusAccepted, w.Code)

			var resp map[string]any
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
			data, ok := resp["data"].(map[string]any)
			require.True(t, ok)
			assert.NotEmpty(t, data["message"])
		})
	}
}

// A2 negative: missing email field → 400 VALIDATION_ERROR.
func TestHandler_ForgotPassword_ValidationError(t *testing.T) {
	t.Parallel()

	r := buildResetRouter(t, newResetUserStore(), newResetTokenStore())
	w := postResetJSON(t, r, "/v1/auth/forgot-password", map[string]any{})

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var resp map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	errBody := resp["error"].(map[string]any)
	assert.Equal(t, "VALIDATION_ERROR", errBody["code"])
}

// A3: ResetPassword happy path → 200 {reset: true}.
func TestHandler_ResetPassword_HappyPath(t *testing.T) {
	t.Parallel()

	users := newResetUserStore()
	resets := newResetTokenStore()
	u := seedHandlerUser(users, "reset-ok@example.com")
	seedHandlerResetToken(resets, u.ID, "good-handler-token", time.Now().UTC().Add(time.Hour), nil)

	r := buildResetRouter(t, users, resets)

	// Use a strong password (≥12 chars, complexity ok).
	w := postResetJSON(t, r, "/v1/auth/reset-password", map[string]any{
		"token":       "good-handler-token",
		"newPassword": "StrongNewPassword99!",
	})

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	data, ok := resp["data"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, true, data["reset"])
}

// A4: Expired token → 400 INVALID_RESET_TOKEN.
func TestHandler_ResetPassword_ExpiredToken(t *testing.T) {
	t.Parallel()

	users := newResetUserStore()
	resets := newResetTokenStore()
	u := seedHandlerUser(users, "reset-expired@example.com")
	seedHandlerResetToken(resets, u.ID, "expired-handler-token", time.Now().UTC().Add(-time.Hour), nil)

	r := buildResetRouter(t, users, resets)
	w := postResetJSON(t, r, "/v1/auth/reset-password", map[string]any{
		"token":       "expired-handler-token",
		"newPassword": "StrongNewPassword99!",
	})

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var resp map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	errBody := resp["error"].(map[string]any)
	assert.Equal(t, "INVALID_RESET_TOKEN", errBody["code"])
}

// ErrWeakPassword from service (hypothetical: service rejects via MeetsComplexity)
// is covered by the service unit tests (A8). At the handler level, the binding
// min=12 gate fires before the service is called for passwords < 12 chars.
// This test confirms the binding returns 400 VALIDATION_ERROR for a too-short password.
func TestHandler_ResetPassword_WeakPasswordBinding(t *testing.T) {
	t.Parallel()

	r := buildResetRouter(t, newResetUserStore(), newResetTokenStore())

	// 6-char password: below binding min=12 → 400 VALIDATION_ERROR.
	w := postResetJSON(t, r, "/v1/auth/reset-password", map[string]any{
		"token":       "some-token",
		"newPassword": "abc123",
	})

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var resp map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	errBody := resp["error"].(map[string]any)
	assert.Equal(t, "VALIDATION_ERROR", errBody["code"])
}

// Unknown token → 400 INVALID_RESET_TOKEN.
func TestHandler_ResetPassword_UnknownToken(t *testing.T) {
	t.Parallel()

	r := buildResetRouter(t, newResetUserStore(), newResetTokenStore())
	w := postResetJSON(t, r, "/v1/auth/reset-password", map[string]any{
		"token":       "never-issued",
		"newPassword": "StrongNewPassword99!",
	})

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var resp map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	errBody := resp["error"].(map[string]any)
	assert.Equal(t, "INVALID_RESET_TOKEN", errBody["code"])
}

// Missing token → 400 VALIDATION_ERROR.
func TestHandler_ResetPassword_MissingToken(t *testing.T) {
	t.Parallel()

	r := buildResetRouter(t, newResetUserStore(), newResetTokenStore())
	w := postResetJSON(t, r, "/v1/auth/reset-password", map[string]any{
		"newPassword": "StrongNewPassword99!",
	})

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var resp map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	errBody := resp["error"].(map[string]any)
	assert.Equal(t, "VALIDATION_ERROR", errBody["code"])
}

// Missing newPassword → 400 VALIDATION_ERROR.
func TestHandler_ResetPassword_MissingPassword(t *testing.T) {
	t.Parallel()

	r := buildResetRouter(t, newResetUserStore(), newResetTokenStore())
	w := postResetJSON(t, r, "/v1/auth/reset-password", map[string]any{
		"token": "some-token",
	})

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var resp map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	errBody := resp["error"].(map[string]any)
	assert.Equal(t, "VALIDATION_ERROR", errBody["code"])
}
