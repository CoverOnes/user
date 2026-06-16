package handler

import (
	"crypto/subtle"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"unicode"

	"github.com/CoverOnes/user/internal/crypto/pii"
	"github.com/CoverOnes/user/internal/domain"
	"github.com/CoverOnes/user/internal/platform/httpx"
	"github.com/CoverOnes/user/internal/store"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"golang.org/x/text/unicode/norm"
)

// identityMatchRequest is the JSON body sent by the kyc service.
type identityMatchRequest struct {
	NationalID string `json:"nationalId"`
	LegalName  string `json:"legalName"`
}

// IdentityMatchHandler handles POST /internal/v1/users/:userId/verify-identity-match.
//
// Security:
//   - Protected by RequireServiceIdentity middleware (caller presents X-Service-Token).
//   - The decrypted national_id and legal_name are NEVER returned, logged, or wrapped in errors.
//   - Only {idMatch, nameMatch} booleans are returned (kyc service never sees decrypted PII).
//   - IDOR-safe: userID comes from the URL path, verified by the caller (kyc service) against
//     its own gateway-injected user identity.
type IdentityMatchHandler struct {
	users     store.UserStore
	encryptor *pii.Encryptor
}

// NewIdentityMatchHandler returns an IdentityMatchHandler.
func NewIdentityMatchHandler(users store.UserStore, encryptor *pii.Encryptor) *IdentityMatchHandler {
	return &IdentityMatchHandler{users: users, encryptor: encryptor}
}

// VerifyIdentityMatch handles POST /internal/v1/users/:userId/verify-identity-match.
//
// Returns {idMatch:bool, nameMatch:bool}. Decrypted PII NEVER leaves this handler.
func (h *IdentityMatchHandler) VerifyIdentityMatch(c *gin.Context) {
	// Body limit: cap at maxBodyBytes (1 MiB) before binding to prevent DoS.
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxBodyBytes)

	userIDStr := c.Param("userId")

	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		httpx.ErrCode(c, http.StatusBadRequest, "INVALID_USER_ID", "userId must be a valid UUID")
		return
	}

	var req identityMatchRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		httpx.ErrCode(c, http.StatusBadRequest, "INVALID_REQUEST_BODY", "request body must be valid JSON with nationalId and legalName")
		return
	}

	if req.NationalID == "" || req.LegalName == "" {
		httpx.ErrCode(c, http.StatusBadRequest, "MISSING_FIELDS", "nationalId and legalName are required")
		return
	}

	u, err := h.users.GetByID(c.Request.Context(), userID)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			httpx.ErrCode(c, http.StatusNotFound, "USER_NOT_FOUND", "user not found")
			return
		}

		httpx.Err(c, err)

		return
	}

	// Decrypt stored PII. Log a warning on failure but do NOT expose the error
	// (decryption failure reveals information about ciphertext shape).
	idMatch := matchNationalID(h.encryptor, u.NationalIDEnc, req.NationalID)
	nameMatch := matchLegalName(h.encryptor, u.LegalNameEnc, req.LegalName)

	slog.Debug(
		"identity match checked",
		"user_id", userID,
		"id_match", idMatch,
		"name_match", nameMatch,
		// Raw PII fields NEVER appear here — only boolean outcomes.
	)

	httpx.OK(c, gin.H{
		"idMatch":   idMatch,
		"nameMatch": nameMatch,
	})
}

// matchNationalID decrypts the stored national_id ciphertext and compares byte-exact
// using constant-time comparison to prevent timing side-channel leaks.
// Returns false on decryption failure (wrong key / no PII set / ciphertext tampered).
// The decrypted plaintext is never exposed outside this function.
func matchNationalID(enc *pii.Encryptor, ciphertext []byte, candidate string) bool {
	if len(ciphertext) == 0 {
		return false
	}

	plaintext, err := enc.Decrypt(ciphertext)
	if err != nil {
		// Logged at Warn only — do not include ciphertext or candidate in the log.
		slog.Warn("national_id decrypt failed during identity match")
		return false
	}

	return subtle.ConstantTimeCompare([]byte(plaintext), []byte(candidate)) == 1
}

// matchLegalName decrypts the stored legal_name ciphertext and compares with normalization
// using constant-time comparison to prevent timing side-channel leaks.
// Both sides are Unicode-NFC-normalized (not NFKC — NFC preserves full-width CJK characters
// that are legally significant on Taiwan government documents), then whitespace-trimmed and collapsed.
// Returns false on decryption failure.
// The decrypted plaintext is never exposed outside this function.
func matchLegalName(enc *pii.Encryptor, ciphertext []byte, candidate string) bool {
	if len(ciphertext) == 0 {
		return false
	}

	plaintext, err := enc.Decrypt(ciphertext)
	if err != nil {
		slog.Warn("legal_name decrypt failed during identity match")
		return false
	}

	a := normalizeName(plaintext)
	b := normalizeName(candidate)

	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// normalizeName applies NFC unicode normalization then collapses whitespace.
// NFC is used (not NFKC) to preserve full-width CJK characters that are legally
// significant on Taiwan government-issued identity documents.
func normalizeName(s string) string {
	nfc := norm.NFC.String(s)
	return strings.Join(strings.FieldsFunc(nfc, unicode.IsSpace), " ")
}
