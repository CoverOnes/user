package handler_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/CoverOnes/user/internal/auth/jwt"
	"github.com/CoverOnes/user/internal/crypto/pii"
	"github.com/CoverOnes/user/internal/domain"
	"github.com/CoverOnes/user/internal/handler"
	"github.com/CoverOnes/user/internal/platform/middleware"
	"github.com/CoverOnes/user/internal/service"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mfaHandlerTestKey is a 32-byte AES-256 key for the real pii.Encryptor used in
// these handler tests (so ciphertext-at-rest is genuinely exercised).
var mfaHandlerTestKey = []byte("fedcba9876543210fedcba9876543210")

// buildMFARouter wires a minimal Gin engine with the /v1/me/mfa/totp/* routes and a
// real encryptor over a fake user store seeded with one ACTIVE user.
func buildMFARouter(t *testing.T) (*gin.Engine, string, *fakeUserStore, uuid.UUID) {
	t.Helper()

	signer, err := jwt.NewEphemeralSigner(10 * time.Minute)
	require.NoError(t, err)

	enc, err := pii.NewEncryptor(mfaHandlerTestKey)
	require.NoError(t, err)

	userStore := newFakeUserStore()
	id := uuid.New()
	now := time.Now().UTC()
	require.NoError(t, userStore.Create(context.Background(), &domain.User{
		ID:          id,
		Email:       "mfa-handler@example.com",
		DisplayName: "MFA User",
		AccountType: domain.AccountTypePersonal,
		Status:      domain.UserStatusActive,
		CreatedAt:   now,
		UpdatedAt:   now,
	}))

	mfaSvc := service.NewMFAService(userStore, enc, "CoverOnes")

	r := gin.New()
	r.Use(middleware.Recover())

	me := r.Group("/v1/me")
	me.Use(middleware.Auth(signer))
	mfaH := handler.NewMFAHandler(mfaSvc)
	totpG := me.Group("/mfa/totp")
	totpG.POST("/enroll", mfaH.Enroll)
	totpG.POST("/confirm", mfaH.Confirm)
	totpG.POST("/verify", mfaH.Verify)
	totpG.POST("/disable", mfaH.Disable)

	token, err := signer.Issue(id.String(), domain.AccountTypePersonal, 0, 0, false)
	require.NoError(t, err)

	return r, token, userStore, id
}

func postJSONAuth(t *testing.T, r http.Handler, path, token string, body any) *httptest.ResponseRecorder {
	t.Helper()

	var buf bytes.Buffer
	if body != nil {
		require.NoError(t, json.NewEncoder(&buf).Encode(body))
	}

	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, path, &buf)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	return w
}

// decodeData unmarshals the {"data": ...} envelope into out.
func decodeData(t *testing.T, w *httptest.ResponseRecorder, out any) {
	t.Helper()

	var env struct {
		Data json.RawMessage `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &env))
	require.NoError(t, json.Unmarshal(env.Data, out))
}

func handlerCode(t *testing.T, secret string) string {
	t.Helper()
	code, err := totp.GenerateCodeCustom(secret, time.Now(), totp.ValidateOpts{
		Period:    30,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	require.NoError(t, err)

	return code
}

func TestMFAHandler_EnrollConfirmVerifyDisable_FullFlow(t *testing.T) {
	r, token, _, _ := buildMFARouter(t)

	// Enroll → 200 with otpauthUri + secret.
	w := postJSONAuth(t, r, "/v1/me/mfa/totp/enroll", token, nil)
	require.Equal(t, http.StatusOK, w.Code, "enroll body: %s", w.Body.String())

	var enroll struct {
		OtpauthURI string `json:"otpauthUri"`
		Secret     string `json:"secret"`
	}
	decodeData(t, w, &enroll)
	assert.Contains(t, enroll.OtpauthURI, "otpauth://totp/CoverOnes:")
	assert.NotEmpty(t, enroll.Secret)

	// Confirm with a valid code → 200 + backup codes + mfaEnabled true.
	w = postJSONAuth(t, r, "/v1/me/mfa/totp/confirm", token, map[string]string{"code": handlerCode(t, enroll.Secret)})
	require.Equal(t, http.StatusOK, w.Code, "confirm body: %s", w.Body.String())

	var confirm struct {
		MFAEnabled  bool     `json:"mfaEnabled"`
		BackupCodes []string `json:"backupCodes"`
	}
	decodeData(t, w, &confirm)
	assert.True(t, confirm.MFAEnabled)
	assert.Len(t, confirm.BackupCodes, 10)

	// Verify with a valid code → 200 valid true.
	w = postJSONAuth(t, r, "/v1/me/mfa/totp/verify", token, map[string]string{"code": handlerCode(t, enroll.Secret)})
	require.Equal(t, http.StatusOK, w.Code, "verify body: %s", w.Body.String())

	var verify struct {
		Valid bool `json:"valid"`
	}
	decodeData(t, w, &verify)
	assert.True(t, verify.Valid)

	// Disable with a valid code → 200 mfaEnabled false.
	w = postJSONAuth(t, r, "/v1/me/mfa/totp/disable", token, map[string]string{"code": handlerCode(t, enroll.Secret)})
	require.Equal(t, http.StatusOK, w.Code, "disable body: %s", w.Body.String())
}

func TestMFAHandler_Confirm_WrongCode400(t *testing.T) {
	r, token, _, _ := buildMFARouter(t)

	w := postJSONAuth(t, r, "/v1/me/mfa/totp/enroll", token, nil)
	require.Equal(t, http.StatusOK, w.Code)

	w = postJSONAuth(t, r, "/v1/me/mfa/totp/confirm", token, map[string]string{"code": "000000"})
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "INVALID_TOTP_CODE")
}

func TestMFAHandler_Verify_InvalidWhenNotEnrolled409(t *testing.T) {
	r, token, _, _ := buildMFARouter(t)

	// No enroll/confirm → user is not mfa-enabled → MFA_NOT_ENROLLED (409).
	w := postJSONAuth(t, r, "/v1/me/mfa/totp/verify", token, map[string]string{"code": "123456"})
	assert.Equal(t, http.StatusConflict, w.Code)
	assert.Contains(t, w.Body.String(), "MFA_NOT_ENROLLED")
}

func TestMFAHandler_Confirm_EmptyBody400(t *testing.T) {
	r, token, _, _ := buildMFARouter(t)

	// Missing "code" field → binding validation 400 (required).
	w := postJSONAuth(t, r, "/v1/me/mfa/totp/confirm", token, map[string]string{})
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "VALIDATION_ERROR")
}

func TestMFAHandler_Unauthorized(t *testing.T) {
	r, _, _, _ := buildMFARouter(t)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/me/mfa/totp/enroll", http.NoBody)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestMFAHandler_Enroll_AlreadyEnabled409(t *testing.T) {
	r, token, userStore, id := buildMFARouter(t)

	u, err := userStore.GetByID(context.Background(), id)
	require.NoError(t, err)
	u.MFAEnabled = true

	w := postJSONAuth(t, r, "/v1/me/mfa/totp/enroll", token, nil)
	assert.Equal(t, http.StatusConflict, w.Code)
	assert.Contains(t, w.Body.String(), "MFA_ALREADY_ENABLED")
}
