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

// translate maps domain / sentinel errors to HTTP status + machine code.
// The details return is reserved for future structured error payloads; currently always nil.
//
//nolint:unparam // details: reserved for structured error payload; always nil today but part of the stable contract
func translate(err error) (code string, status int, message string, details any) {
	switch {
	case errors.Is(err, domain.ErrNotFound):
		return "USER_NOT_FOUND", http.StatusNotFound, "user not found", nil

	case errors.Is(err, domain.ErrEmailTaken):
		return "EMAIL_TAKEN", http.StatusConflict, "email is already registered", nil

	case errors.Is(err, domain.ErrInvalidCredentials):
		return "INVALID_CREDENTIALS", http.StatusUnauthorized, "invalid email or password", nil

	case errors.Is(err, domain.ErrLoginRateLimited):
		return "RATE_LIMITED", http.StatusTooManyRequests, "too many login attempts, please try again later", nil

	case errors.Is(err, domain.ErrAccountSuspended):
		return "ACCOUNT_SUSPENDED", http.StatusForbidden, "account is suspended", nil

	case errors.Is(err, domain.ErrWeakPassword):
		return "WEAK_PASSWORD", http.StatusUnprocessableEntity, "password does not meet requirements", nil

	case errors.Is(err, domain.ErrInvalidRefresh):
		return "INVALID_REFRESH_TOKEN", http.StatusUnauthorized, "invalid refresh token", nil

	case errors.Is(err, domain.ErrRefreshExpired):
		return "REFRESH_EXPIRED", http.StatusUnauthorized, "refresh token has expired", nil

	case errors.Is(err, domain.ErrRefreshReuse):
		return "REFRESH_REUSE_DETECTED", http.StatusUnauthorized, "token reuse detected; all sessions revoked", nil

	case errors.Is(err, domain.ErrKYCTierRequired):
		return "KYC_TIER_REQUIRED", http.StatusForbidden, "kyc verification required", nil

	case errors.Is(err, domain.ErrUnauthorized):
		return "UNAUTHORIZED", http.StatusUnauthorized, "unauthorized", nil

	case errors.Is(err, domain.ErrCompanyNameRequired):
		return codeValidationError, http.StatusBadRequest, err.Error(), nil

	case errors.Is(err, domain.ErrCompanyNameTooLong):
		return codeValidationError, http.StatusBadRequest, err.Error(), nil

	case errors.Is(err, domain.ErrValidation):
		return codeValidationError, http.StatusBadRequest, err.Error(), nil

	default:
		slog.Error("unhandled internal error", "err", err)
		return "INTERNAL_ERROR", http.StatusInternalServerError, "internal server error", nil
	}
}
