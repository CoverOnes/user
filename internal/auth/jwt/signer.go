package jwt

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// Signer handles EdDSA JWT sign and verify operations.
type Signer struct {
	privateKey ed25519.PrivateKey
	publicKey  ed25519.PublicKey
	kid        string
	ttl        time.Duration
}

// NewSignerFromSeed creates a Signer from a base64-encoded 32-byte Ed25519 seed.
func NewSignerFromSeed(seedB64 string, ttl time.Duration) (*Signer, error) {
	seedBytes, err := base64.StdEncoding.DecodeString(seedB64)
	if err != nil {
		// Try URL-safe encoding.
		seedBytes, err = base64.RawURLEncoding.DecodeString(seedB64)
		if err != nil {
			return nil, fmt.Errorf("decode ed25519 seed: %w", err)
		}
	}

	if len(seedBytes) != ed25519.SeedSize {
		return nil, fmt.Errorf("ed25519 seed must be %d bytes, got %d", ed25519.SeedSize, len(seedBytes))
	}

	priv := ed25519.NewKeyFromSeed(seedBytes)
	pub := priv.Public().(ed25519.PublicKey)

	return &Signer{
		privateKey: priv,
		publicKey:  pub,
		kid:        kidFromPub(pub),
		ttl:        ttl,
	}, nil
}

// NewEphemeralSigner generates a new random Ed25519 key pair (dev mode only).
func NewEphemeralSigner(ttl time.Duration) (*Signer, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ed25519 key: %w", err)
	}

	slog.Warn("EPHEMERAL ED25519 KEY in use — tokens will not survive restart; set USER_JWT_PRIVATE_KEY for production")

	return &Signer{
		privateKey: priv,
		publicKey:  pub,
		kid:        kidFromPub(pub),
		ttl:        ttl,
	}, nil
}

// kidFromPub derives a deterministic KID from the public key.
// Takes the first 8 bytes of SHA-256(pubkey) and encodes them as base64url
// without padding, yielding an 11-character string (F16: was incorrectly
// documented as "first 16 chars").
func kidFromPub(pub ed25519.PublicKey) string {
	h := sha256.Sum256(pub)
	return base64.RawURLEncoding.EncodeToString(h[:8]) // 8 bytes → 11 base64url chars
}

// Issue signs a new access token for the given user attributes.
func (s *Signer) Issue(userID, accountType string, kycTier int16, tokenVersion int, emailVerified bool) (string, error) {
	now := time.Now().UTC()
	jti := uuid.New().String()

	claims := &Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    Issuer,
			Subject:   userID,
			Audience:  jwt.ClaimStrings{Audience},
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(s.ttl)),
			ID:        jti,
		},
		KYCTier:       kycTier,
		AccountType:   accountType,
		TokenVersion:  tokenVersion,
		EmailVerified: emailVerified,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	token.Header["kid"] = s.kid

	signed, err := token.SignedString(s.privateKey)
	if err != nil {
		return "", fmt.Errorf("sign jwt: %w", err)
	}

	return signed, nil
}

// Verify parses and validates a JWT string, returning the embedded claims.
// It rejects alg=none and any non-EdDSA algorithm.
func (s *Signer) Verify(tokenStr string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(
		tokenStr, &Claims{},
		func(t *jwt.Token) (any, error) {
			return s.publicKey, nil
		},
		jwt.WithValidMethods([]string{"EdDSA"}),
		jwt.WithLeeway(5*time.Second), // 5 s leeway — ≤1% of a 600 s TTL (F11)
		jwt.WithIssuedAt(),
		jwt.WithIssuer(Issuer),
		jwt.WithAudience(Audience),
		jwt.WithExpirationRequired(),
	)
	if err != nil {
		return nil, fmt.Errorf("invalid jwt: %w", err)
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, errors.New("invalid jwt claims")
	}

	return claims, nil
}

// PublicKey returns the Ed25519 public key for JWKS publication.
func (s *Signer) PublicKey() ed25519.PublicKey {
	return s.publicKey
}

// KID returns the key identifier.
func (s *Signer) KID() string {
	return s.kid
}
