package handler_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/CoverOnes/user/internal/auth/jwt"
	"github.com/CoverOnes/user/internal/crypto/pii"
	"github.com/CoverOnes/user/internal/handler"
	"github.com/CoverOnes/user/internal/platform/middleware"
	"github.com/CoverOnes/user/internal/service"
	"github.com/CoverOnes/user/internal/store/postgres"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Note: startTestDBForHandler and runMigrationsForHandler are defined in
// session_integration_test.go (same package handler_test) and are reused here.

// newTestEncryptor generates a random 32-byte key and returns a PII Encryptor for testing.
func newTestEncryptor(t *testing.T) *pii.Encryptor {
	t.Helper()

	key := make([]byte, pii.KeySize)
	_, err := rand.Read(key)
	require.NoError(t, err)

	enc, err := pii.NewEncryptor(key)
	require.NoError(t, err)

	return enc
}

// buildIdentityMatchRouter builds a minimal gin router with only the S2S identity-match route.
func buildIdentityMatchRouter(
	t *testing.T,
	s2sToken string,
	userStore *postgres.UserStore,
	encryptor *pii.Encryptor,
) *gin.Engine {
	t.Helper()

	r := gin.New()
	r.Use(middleware.Recover())

	matchH := handler.NewIdentityMatchHandler(userStore, encryptor)
	internal := r.Group("/internal/v1/users")
	internal.Use(middleware.RequireServiceIdentity(s2sToken))
	internal.POST("/:userId/verify-identity-match", matchH.VerifyIdentityMatch)

	return r
}

// issueIdentityMatch issues POST /internal/v1/users/:userId/verify-identity-match.
func issueIdentityMatch(
	t *testing.T,
	r *gin.Engine,
	userID uuid.UUID,
	s2sToken string,
	nationalID string,
	legalName string,
) *httptest.ResponseRecorder {
	t.Helper()

	body, err := json.Marshal(map[string]string{
		"nationalId": nationalID,
		"legalName":  legalName,
	})
	require.NoError(t, err)

	path := fmt.Sprintf("/internal/v1/users/%s/verify-identity-match", userID)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, path, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	if s2sToken != "" {
		req.Header.Set("X-Service-Token", s2sToken)
	}

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	return w
}

// TestVerifyIdentityMatch_Integration tests the full S2S identity-match endpoint
// against a real Postgres container. It verifies:
//
//   - Happy path: both idMatch and nameMatch are true when plaintext equals encrypted value
//   - ID match but name mismatch → {idMatch:true, nameMatch:false}
//   - Both mismatch → {idMatch:false, nameMatch:false}
//   - User not found → 404
//   - Missing S2S token → 401
//   - Wrong S2S token → 401
//   - Unicode normalization: extra whitespace in name collapses and still matches
//   - COMPANY account (NationalIDEnc nil) → idMatch:false even when name matches
func TestVerifyIdentityMatch_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping identity-match integration test in short mode")
	}

	ctx := context.Background()
	dsn := startTestDBForHandler(t)
	runMigrationsForHandler(t, ctx, dsn)

	pool, err := postgres.NewPool(ctx, dsn, "", 0, 0)
	require.NoError(t, err)
	defer pool.Close()

	// Use a fresh random 32-byte key. Both AuthService (encryption) and
	// IdentityMatchHandler (decryption) must share the SAME encryptor instance
	// so round-trip works.
	encryptor := newTestEncryptor(t)
	userStore := postgres.NewUserStore(pool)
	companyStore := postgres.NewCompanyStore(pool)
	rtStore := postgres.NewRefreshTokenStore(pool)
	txMgr := postgres.NewTxManager(pool)

	// ephemeral signer — only required to satisfy AuthService construction.
	signer, err := jwt.NewEphemeralSigner(10 * time.Minute)
	require.NoError(t, err)

	// Wire the encryptor into AuthService so Register encrypts PII with the same key
	// that IdentityMatchHandler will use for decryption. Mailer is nil (tests do not
	// need email dispatch; Register still creates the user with encrypted PII).
	authSvc := service.NewAuthService(
		userStore, companyStore, rtStore, txMgr,
		signer, 10*time.Minute, 24,
	).WithVerification(nil, encryptor, nil, nil)

	const s2sToken = "thisis-a-very-long-s2s-token-abcdefghij"

	r := buildIdentityMatchRouter(t, s2sToken, userStore, encryptor)

	// Register a PERSONAL user. LegalNameEnc and NationalIDEnc are both set.
	personalOut, err := authSvc.Register(ctx, service.RegisterInput{
		Email:       "id-match-integration@example.test",
		Password:    "SuperSecurePassword999",
		DisplayName: "Identity Match User",
		AccountType: "PERSONAL",
		LegalName:   "王小明",
		NationalID:  "A123456789", // checksum-valid TW national ID fixture
	})
	require.NoError(t, err)

	personalUserID := personalOut.User.ID

	// Register a COMPANY user. NationalIDEnc is nil; LegalNameEnc is set.
	companyOut, err := authSvc.Register(ctx, service.RegisterInput{
		Email:       "id-match-company@example.test",
		Password:    "SuperSecurePassword999",
		DisplayName: "Company Corp",
		AccountType: "COMPANY",
		LegalName:   "Company Legal Name",
		CompanyName: "Company Corp",
	})
	require.NoError(t, err)

	companyUserID := companyOut.User.ID

	tests := []struct {
		name          string
		userID        uuid.UUID
		token         string
		nationalID    string
		legalName     string
		wantStatus    int
		wantIDMatch   *bool
		wantNameMatch *bool
	}{
		{
			name:          "happy path: both match",
			userID:        personalUserID,
			token:         s2sToken,
			nationalID:    "A123456789",
			legalName:     "王小明",
			wantStatus:    http.StatusOK,
			wantIDMatch:   boolPtr(true),
			wantNameMatch: boolPtr(true),
		},
		{
			name:          "id match but name mismatch",
			userID:        personalUserID,
			token:         s2sToken,
			nationalID:    "A123456789",
			legalName:     "李大海",
			wantStatus:    http.StatusOK,
			wantIDMatch:   boolPtr(true),
			wantNameMatch: boolPtr(false),
		},
		{
			name:          "both mismatch",
			userID:        personalUserID,
			token:         s2sToken,
			nationalID:    "B123456789",
			legalName:     "李大海",
			wantStatus:    http.StatusOK,
			wantIDMatch:   boolPtr(false),
			wantNameMatch: boolPtr(false),
		},
		{
			name:       "user not found returns 404",
			userID:     uuid.New(),
			token:      s2sToken,
			nationalID: "A123456789",
			legalName:  "王小明",
			wantStatus: http.StatusNotFound,
		},
		{
			name:       "missing s2s token returns 401",
			userID:     personalUserID,
			token:      "",
			nationalID: "A123456789",
			legalName:  "王小明",
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "wrong s2s token returns 401",
			userID:     personalUserID,
			token:      "wrong-token",
			nationalID: "A123456789",
			legalName:  "王小明",
			wantStatus: http.StatusUnauthorized,
		},
		{
			// normalizeName calls strings.FieldsFunc which strips leading and trailing
			// whitespace. "  王小明  " (leading + trailing spaces) normalizes to "王小明"
			// which matches the stored value "王小明" after the same normalization.
			name:          "unicode normalization: leading and trailing whitespace stripped",
			userID:        personalUserID,
			token:         s2sToken,
			nationalID:    "A123456789",
			legalName:     "  王小明  ",
			wantStatus:    http.StatusOK,
			wantIDMatch:   boolPtr(true),
			wantNameMatch: boolPtr(true),
		},
		{
			// COMPANY account: NationalIDEnc is nil → idMatch must be false.
			// LegalNameEnc IS set (legal name always required/encrypted).
			// nameMatch is true when the legal name matches.
			name:          "company account: idMatch false because NationalIDEnc nil",
			userID:        companyUserID,
			token:         s2sToken,
			nationalID:    "A123456789",
			legalName:     "Company Legal Name",
			wantStatus:    http.StatusOK,
			wantIDMatch:   boolPtr(false),
			wantNameMatch: boolPtr(true),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp := issueIdentityMatch(t, r, tc.userID, tc.token, tc.nationalID, tc.legalName)
			assert.Equal(t, tc.wantStatus, resp.Code, "unexpected HTTP status for %q", tc.name)

			if tc.wantIDMatch == nil {
				// Non-200 response — status check is sufficient.
				return
			}

			var envelope struct {
				Data map[string]any `json:"data"`
			}
			require.NoError(t, json.Unmarshal(resp.Body.Bytes(), &envelope), "response body must be valid JSON")
			require.NotNil(t, envelope.Data, "response data must not be nil")

			assert.Equal(t, *tc.wantIDMatch, envelope.Data["idMatch"], "idMatch mismatch for %q", tc.name)
			assert.Equal(t, *tc.wantNameMatch, envelope.Data["nameMatch"], "nameMatch mismatch for %q", tc.name)

			// PII non-leak: decrypted national_id and legal_name MUST NOT appear in
			// any 200 response body — only boolean results are returned.
			body := resp.Body.String()
			assert.NotContains(t, body, "A123456789", "response must not contain plaintext national_id")
			assert.NotContains(t, body, "王小明", "response must not contain plaintext legal_name")
		})
	}
}

// boolPtr returns a pointer to the given bool, used in test table initialization.
func boolPtr(b bool) *bool {
	return &b
}
