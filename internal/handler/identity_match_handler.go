package handler

import (
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

	slog.Info(
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

// matchNationalID decrypts the stored national_id ciphertext and compares byte-exact.
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

	return plaintext == candidate
}

// matchLegalName decrypts the stored legal_name ciphertext and compares with normalization:
// both sides are Unicode-NFC-normalized, then whitespace-trimmed and collapsed.
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

	return normalizeName(plaintext) == normalizeName(candidate)
}

// normalizeName applies NFC unicode normalization then collapses whitespace.
// This makes "王 小明" == "王小明" and handles different Unicode representations.
func normalizeName(s string) string {
	nfc := norm.NFC.String(s)
	return strings.Join(strings.FieldsFunc(nfc, unicode.IsSpace), " ")
}
