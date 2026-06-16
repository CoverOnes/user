package domain

import "errors"

// Sentinel errors for the domain layer.
var (
	ErrNotFound            = errors.New("not found")
	ErrEmailTaken          = errors.New("email already taken")
	ErrHandleTaken         = errors.New("handle already taken")
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

	// OAuth errors (Increment 4).

	// ErrOAuthStateInvalid is returned when the OAuth state/PKCE verification fails
	// (replay, CSRF, expired state, PKCE verifier mismatch). Maps to HTTP 400.
	ErrOAuthStateInvalid = errors.New("oauth state invalid or expired")

	// ErrOAuthExchangeFailed is returned when the token exchange with the provider
	// fails (network, invalid code, etc.). Maps to HTTP 502.
	ErrOAuthExchangeFailed = errors.New("oauth token exchange failed")

	// ErrOAuthProviderUnknown is returned when the provider parameter is not in
	// the allowlist. Maps to HTTP 404.
	ErrOAuthProviderUnknown = errors.New("unknown oauth provider")

	// ErrOAuthOneTimeCodeInvalid is returned when the frontend one-time code
	// is missing, expired, or already consumed. Maps to HTTP 400.
	ErrOAuthOneTimeCodeInvalid = errors.New("oauth one-time code invalid or expired")

	// ErrIdentityAlreadyBound is returned when POST /v1/me/identities/:provider finds
	// the (provider, provider_subject) pair already linked to any user. Maps to HTTP 409.
	ErrIdentityAlreadyBound = errors.New("oauth identity already bound to an account")

	// ErrLastLoginMethod is returned by Unbind when removing the identity would leave
	// the user with no remaining login method. Maps to HTTP 409.
	ErrLastLoginMethod = errors.New("cannot remove last login method")

	// ErrInvalidResetToken is the single generic error for ALL password-reset
	// failure modes (not-found / expired / already-used). One code, no oracle
	// that would let a caller distinguish the cases.
	ErrInvalidResetToken = errors.New("invalid password reset token")

	// Connection errors (P4 Network, migration 000010).

	// ErrConnectionExists is returned when a live (pending|accepted) edge already
	// exists for the unordered pair of users — surfaced from the partial-unique
	// index 23505 on connections_pair_live_uniq. Maps to HTTP 409.
	ErrConnectionExists = errors.New("connection already exists")

	// ErrConnectionNotFound is returned when an accept/decline targets a connection
	// id that has no PENDING row addressed to the caller. It is intentionally the
	// SAME error for "id does not exist" and "id exists but you are not the
	// addressee" — IDOR-safe (404, no 403 oracle that would leak edge existence).
	// Maps to HTTP 404.
	ErrConnectionNotFound = errors.New("connection not found")

	// ErrConnectionNotPending is returned when the caller IS the addressee of the
	// targeted connection but it has already been resolved (accepted/declined), so
	// the guarded UPDATE matched no pending row. Distinct from ErrConnectionNotFound
	// so a legitimate owner gets a precise 409 rather than a misleading 404.
	ErrConnectionNotPending = errors.New("connection is not pending")

	// Company errors (P4 Company, migration 000011).

	// ErrCompanyNotFound is returned when a company lookup (by id, or via the
	// caller's company_id) matches no row — including the case where the caller has
	// no company_id set. A DISTINCT 404 code (COMPANY_NOT_FOUND) rather than reusing
	// USER_NOT_FOUND (resolved-decision #1), so the frontend can render a
	// company-specific not-found state. Maps to HTTP 404.
	ErrCompanyNotFound = errors.New("company not found")

	// ErrNotCompanyOwner is returned by UpdateMyCompany when the authenticated caller
	// is NOT the company's owner_user_id. Owner-gating is an authorization boundary on
	// a resource the caller can otherwise read, so it is a precise 403 (not a 404):
	// the caller legitimately knows the company exists (it is their own membership),
	// they just may not mutate it. Maps to HTTP 403.
	ErrNotCompanyOwner = errors.New("caller is not the company owner")
)
