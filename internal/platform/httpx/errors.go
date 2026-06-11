package httpx

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/CoverOnes/user/internal/domain"
	"github.com/gin-gonic/gin"
)

// codeValidationError is the stable machine code for input-validation failures (400).
const codeValidationError = "VALIDATION_ERROR"

// ErrorResponse is the machine-readable error envelope.
type ErrorResponse struct {
	Error ErrorBody `json:"error"`
}

// ErrorBody carries the stable code, human message, and optional details.
type ErrorBody struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Details any    `json:"details,omitempty"`
}

// Err sends a structured error response, translating domain errors to HTTP codes.
func Err(c *gin.Context, err error) {
	code, status, message, details := translate(err)
	c.JSON(status, ErrorResponse{Error: ErrorBody{
		Code:    code,
		Message: message,
		Details: details,
	}})
}

// ErrCode sends a raw code/status/message triple (for handler-generated errors
// that don't map cleanly to domain sentinels).
func ErrCode(c *gin.Context, status int, code, message string, details ...any) {
	var d any
	if len(details) > 0 {
		d = details[0]
	}
	c.JSON(status, ErrorResponse{Error: ErrorBody{
		Code:    code,
		Message: message,
		Details: d,
	}})
}

// errMapping is a fixed code/status/message for a sentinel error.
type errMapping struct {
	sentinel error
	code     string
	status   int
	message  string
}

// fixedErrorMappings are sentinels with a CONSTANT client-facing message (no
// error-text passthrough). Order is irrelevant since each errors.Is is exclusive.
var fixedErrorMappings = []errMapping{
	{domain.ErrNotFound, "USER_NOT_FOUND", http.StatusNotFound, "user not found"},
	{domain.ErrEmailTaken, "EMAIL_TAKEN", http.StatusConflict, "email is already registered"},
	{domain.ErrInvalidCredentials, "INVALID_CREDENTIALS", http.StatusUnauthorized, "invalid email or password"},
	{domain.ErrLoginRateLimited, "RATE_LIMITED", http.StatusTooManyRequests, "too many login attempts, please try again later"},
	{domain.ErrAccountSuspended, "ACCOUNT_SUSPENDED", http.StatusForbidden, "account is suspended"},
	{domain.ErrWeakPassword, "WEAK_PASSWORD", http.StatusUnprocessableEntity, "password does not meet requirements"},
	{domain.ErrInvalidRefresh, "INVALID_REFRESH_TOKEN", http.StatusUnauthorized, "invalid refresh token"},
	{domain.ErrRefreshExpired, "REFRESH_EXPIRED", http.StatusUnauthorized, "refresh token has expired"},
	{domain.ErrRefreshReuse, "REFRESH_REUSE_DETECTED", http.StatusUnauthorized, "token reuse detected; all sessions revoked"},
	{domain.ErrKYCTierRequired, "KYC_TIER_REQUIRED", http.StatusForbidden, "kyc verification required"},
	{domain.ErrUnauthorized, "UNAUTHORIZED", http.StatusUnauthorized, "unauthorized"},
	// Single generic code for verify-email not-found / expired / already-consumed — no oracle.
	{domain.ErrInvalidVerificationToken, "INVALID_VERIFICATION_TOKEN", http.StatusBadRequest, "invalid or expired verification token"},
	{domain.ErrEmailNotVerified, "EMAIL_NOT_VERIFIED", http.StatusForbidden, "email verification required"},
	// TOTP 2FA (Increment 3). One generic INVALID_TOTP_CODE for all wrong-code paths (no oracle).
	{domain.ErrInvalidTOTPCode, "INVALID_TOTP_CODE", http.StatusBadRequest, "invalid totp code"},
	{domain.ErrMFANotEnrolled, "MFA_NOT_ENROLLED", http.StatusConflict, "mfa is not enrolled"},
	{domain.ErrMFAAlreadyEnabled, "MFA_ALREADY_ENABLED", http.StatusConflict, "mfa is already enabled"},
	// OAuth social login (Increment 4).
	{domain.ErrOAuthStateInvalid, "OAUTH_STATE_INVALID", http.StatusBadRequest, "oauth state invalid or expired"},
	{domain.ErrOAuthExchangeFailed, "OAUTH_EXCHANGE_FAILED", http.StatusBadGateway, "oauth token exchange failed"},
	{domain.ErrOAuthProviderUnknown, "OAUTH_PROVIDER_UNKNOWN", http.StatusNotFound, "unknown oauth provider"},
	{domain.ErrOAuthOneTimeCodeInvalid, "OAUTH_CODE_INVALID", http.StatusBadRequest, "oauth one-time code invalid or expired"},
	{domain.ErrEmailAlreadyRegistered, "EMAIL_ALREADY_REGISTERED", http.StatusConflict, "email already registered by another account"},
	{domain.ErrIdentityAlreadyBound, "IDENTITY_ALREADY_BOUND", http.StatusConflict, "oauth identity already bound to an account"},
	{domain.ErrLastLoginMethod, "LAST_LOGIN_METHOD", http.StatusConflict, "cannot remove last login method"},
}

// passthroughValidationErrors are validation sentinels whose own Error() text is
// safe to surface to the client (400 VALIDATION_ERROR).
var passthroughValidationErrors = []error{
	domain.ErrCompanyNameRequired,
	domain.ErrCompanyNameTooLong,
	domain.ErrValidation,
}

// translate maps domain / sentinel errors to HTTP status + machine code.
// The details return is reserved for future structured error payloads; currently always nil.
//
//nolint:unparam // details: reserved for structured error payload; always nil today but part of the stable contract
func translate(err error) (code string, status int, message string, details any) {
	for _, m := range fixedErrorMappings {
		if errors.Is(err, m.sentinel) {
			return m.code, m.status, m.message, nil
		}
	}

	for _, v := range passthroughValidationErrors {
		if errors.Is(err, v) {
			return codeValidationError, http.StatusBadRequest, err.Error(), nil
		}
	}

	slog.Error("unhandled internal error", "err", err)

	return "INTERNAL_ERROR", http.StatusInternalServerError, "internal server error", nil
}
