package domain

import "errors"

// Sentinel errors for the domain layer.
var (
	ErrNotFound            = errors.New("not found")
	ErrEmailTaken          = errors.New("email already taken")
	ErrInvalidCredentials  = errors.New("invalid credentials")
	ErrAccountSuspended    = errors.New("account suspended")
	ErrWeakPassword        = errors.New("password too weak")
	ErrInvalidRefresh      = errors.New("invalid refresh token")
	ErrRefreshExpired      = errors.New("refresh token expired")
	ErrRefreshReuse        = errors.New("refresh token reuse detected")
	ErrKYCTierRequired     = errors.New("kyc tier required")
	ErrUnauthorized        = errors.New("unauthorized")
	ErrCompanyNameRequired = errors.New("company name required for COMPANY account type")
	// ErrValidation is returned for input validation failures (maps to HTTP 400).
	// Use ErrInvalidCredentials only for auth-specific failures (maps to HTTP 401).
	ErrValidation = errors.New("validation error")
)
