package domain

import "errors"

// Sentinel errors for the domain layer.
var (
	ErrNotFound            = errors.New("not found")
	ErrEmailTaken          = errors.New("email already taken")
	ErrInvalidCredentials  = errors.New("invalid credentials")
	ErrAccountSuspended    = errors.New("account suspended")
	ErrLoginRateLimited    = errors.New("too many login attempts")
	ErrWeakPassword        = errors.New("password too weak")
	ErrInvalidRefresh      = errors.New("invalid refresh token")
	ErrRefreshExpired      = errors.New("refresh token expired")
	ErrRefreshReuse        = errors.New("refresh token reuse detected")
	ErrKYCTierRequired     = errors.New("kyc tier required")
	ErrUnauthorized        = errors.New("unauthorized")
	ErrCompanyNameRequired = errors.New("company name required for COMPANY account type")
	ErrCompanyNameTooLong  = errors.New("company name must be at most 200 characters")
	// ErrEmailNotVerified is returned by the RequireEmailVerified middleware when a
	// verified JWT carries email_verified=false (maps to HTTP 403).
	ErrEmailNotVerified = errors.New("email not verified")
	// ErrInvalidVerificationToken is the single generic error for ALL verify-email
	// failure modes (not-found / expired / already-consumed). One code, no oracle
	// that would let a caller distinguish the cases.
	ErrInvalidVerificationToken = errors.New("invalid verification token")
	// ErrValidation is returned for input validation failures (maps to HTTP 400).
	// Use ErrInvalidCredentials only for auth-specific failures (maps to HTTP 401).
	ErrValidation = errors.New("validation error")

	// ErrMFANotEnrolled is returned when confirm/verify/disable is called but the
	// user has no pending or active TOTP secret (maps to HTTP 400/409 as appropriate).
	ErrMFANotEnrolled = errors.New("mfa not enrolled")

	// ErrMFAAlreadyEnabled is returned when enroll is called for a user whose MFA is
	// already enabled (re-enrolling must go through disable first; maps to HTTP 409).
	ErrMFAAlreadyEnabled = errors.New("mfa already enabled")

	// ErrInvalidTOTPCode is the single generic error for ALL TOTP confirm/verify/
	// disable failures (wrong code / expired window). One code, no oracle that would
	// let a caller distinguish the cases (maps to HTTP 400).
	ErrInvalidTOTPCode = errors.New("invalid totp code")
)
