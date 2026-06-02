// Package jwt provides EdDSA JWT signing and verification.
package jwt

import (
	"github.com/golang-jwt/jwt/v5"
)

const (
	// Issuer is the iss claim for all tokens issued by this service.
	Issuer = "coverones-user"
	// Audience is the aud claim expected by downstream services.
	Audience = "coverones"
)

// Claims are the custom JWT claims embedded in access tokens.
type Claims struct {
	jwt.RegisteredClaims

	// KYCTier is the user's current verification tier (0-3).
	KYCTier int16 `json:"kycTier"`

	// AccountType is PERSONAL or COMPANY.
	AccountType string `json:"accountType"`

	// TokenVersion allows global revocation of all tokens when bumped.
	TokenVersion int `json:"tokenVersion"`
}
