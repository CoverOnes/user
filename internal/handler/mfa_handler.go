package handler

import (
	"net/http"

	"github.com/CoverOnes/user/internal/platform/httpx"
	"github.com/CoverOnes/user/internal/platform/middleware"
	"github.com/CoverOnes/user/internal/service"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// MFAHandler handles the TOTP 2FA endpoints under /v1/me/mfa/totp.
// These are PRIMITIVES (enroll / confirm / verify / disable); login is NOT wired
// to them in this increment.
type MFAHandler struct {
	mfa *service.MFAService
}

// NewMFAHandler returns an MFAHandler.
func NewMFAHandler(mfa *service.MFAService) *MFAHandler {
	return &MFAHandler{mfa: mfa}
}

// codeRequest is the {code} body shared by confirm / verify / disable.
type codeRequest struct {
	// Code is the 6-digit TOTP passcode (or, for disable, a one-time backup code).
	// Bound at 1..64 so an empty / absurdly long body is rejected before the service.
	Code string `json:"code" binding:"required,min=1,max=64"`
}

// subjectFromCtx extracts and parses the authenticated user's UUID from the JWT
// claims the Auth middleware injected. It writes the 401 response itself and
// returns ok=false when authentication is missing / malformed.
func subjectFromCtx(c *gin.Context) (uuid.UUID, bool) {
	claims, ok := middleware.ClaimsFromCtx(c)
	if !ok {
		httpx.ErrCode(c, http.StatusUnauthorized, "UNAUTHORIZED", "authentication required")
		return uuid.Nil, false
	}

	id, err := uuid.Parse(claims.Subject)
	if err != nil {
		httpx.ErrCode(c, http.StatusUnauthorized, "UNAUTHORIZED", "invalid token subject")
		return uuid.Nil, false
	}

	return id, true
}

// Enroll handles POST /v1/me/mfa/totp/enroll.
// Generates a new pending TOTP secret (stored encrypted, MFA not yet enabled) and
// returns the otpauth provisioning URI + the base32 secret ONCE.
func (h *MFAHandler) Enroll(c *gin.Context) {
	id, ok := subjectFromCtx(c)
	if !ok {
		return
	}

	out, err := h.mfa.Enroll(c.Request.Context(), id)
	if err != nil {
		httpx.Err(c, err)
		return
	}

	httpx.OK(c, gin.H{
		"otpauthUri": out.OtpauthURI,
		"secret":     out.Secret,
	})
}

// Confirm handles POST /v1/me/mfa/totp/confirm {code}.
// Verifies the code against the pending secret; on success enables MFA and returns
// the one-time backup codes ONCE. A bad code → 400 INVALID_TOTP_CODE.
func (h *MFAHandler) Confirm(c *gin.Context) {
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxBodyBytes)

	id, ok := subjectFromCtx(c)
	if !ok {
		return
	}

	var req codeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		httpx.ErrCode(c, http.StatusBadRequest, "VALIDATION_ERROR", err.Error())
		return
	}

	out, err := h.mfa.Confirm(c.Request.Context(), id, req.Code)
	if err != nil {
		httpx.Err(c, err)
		return
	}

	httpx.OK(c, gin.H{
		"mfaEnabled":  true,
		"backupCodes": out.BackupCodes,
	})
}

// Verify handles POST /v1/me/mfa/totp/verify {code}.
// Verifies a code for an mfa-enabled user (the primitive a future login step will
// call). 200 valid / 400 invalid. NOT called from login in this increment.
func (h *MFAHandler) Verify(c *gin.Context) {
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxBodyBytes)

	id, ok := subjectFromCtx(c)
	if !ok {
		return
	}

	var req codeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		httpx.ErrCode(c, http.StatusBadRequest, "VALIDATION_ERROR", err.Error())
		return
	}

	if err := h.mfa.Verify(c.Request.Context(), id, req.Code); err != nil {
		httpx.Err(c, err)
		return
	}

	httpx.OK(c, gin.H{"valid": true})
}

// Disable handles POST /v1/me/mfa/totp/disable {code}.
// Disables MFA after verifying a current TOTP code (or a one-time backup code).
func (h *MFAHandler) Disable(c *gin.Context) {
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxBodyBytes)

	id, ok := subjectFromCtx(c)
	if !ok {
		return
	}

	var req codeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		httpx.ErrCode(c, http.StatusBadRequest, "VALIDATION_ERROR", err.Error())
		return
	}

	if err := h.mfa.Disable(c.Request.Context(), id, req.Code); err != nil {
		httpx.Err(c, err)
		return
	}

	httpx.OK(c, gin.H{"mfaEnabled": false})
}
