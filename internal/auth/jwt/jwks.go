package jwt

import (
	"encoding/base64"
)

// JWKSKey represents a single JSON Web Key for Ed25519 public keys.
type JWKSKey struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	X   string `json:"x"` // base64url raw public key bytes
}

// JWKS is the JSON Web Key Set published at /jwks.
type JWKS struct {
	Keys []JWKSKey `json:"keys"`
}

// BuildJWKS constructs the JWKS from the signer's public key.
// Only the public key is included — NEVER the seed or private key.
func (s *Signer) BuildJWKS() JWKS {
	x := base64.RawURLEncoding.EncodeToString(s.publicKey)

	return JWKS{
		Keys: []JWKSKey{
			{
				Kty: "OKP",
				Crv: "Ed25519",
				Use: "sig",
				Alg: "EdDSA",
				Kid: s.kid,
				X:   x,
			},
		},
	}
}
