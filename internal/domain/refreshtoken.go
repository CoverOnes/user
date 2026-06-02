package domain

// RefreshTokenStatus groups the possible states a refresh token can be in.
// This is used by the service layer for decision-making, not stored in DB.
type RefreshTokenStatus int

const (
	// RefreshTokenValid means the token is usable.
	RefreshTokenValid RefreshTokenStatus = iota
	// RefreshTokenExpired means expires_at has passed.
	RefreshTokenExpired
	// RefreshTokenRevoked means it was explicitly revoked.
	RefreshTokenRevoked
	// RefreshTokenReused means used_at was already set (reuse attack detected).
	RefreshTokenReused
)
