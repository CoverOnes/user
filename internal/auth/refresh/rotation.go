// Package refresh implements refresh token generation and rotation logic.
package refresh

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"

	"github.com/google/uuid"
)

const (
	secretLen = 32 // 32 random bytes = 256 bits of entropy
)

// Token is a refresh token value object.
type Token struct {
	ID     uuid.UUID
	Secret string // base64url raw, 32 bytes
	Raw    string // "<id>.<secret>" — sent to client
	Hash   []byte // SHA-256(secret) — stored in DB
}

// Generate creates a new random refresh token.
func Generate() (*Token, error) {
	id := uuid.New()

	secretBytes := make([]byte, secretLen)
	if _, err := rand.Read(secretBytes); err != nil {
		return nil, fmt.Errorf("generate refresh token secret: %w", err)
	}

	secret := base64.RawURLEncoding.EncodeToString(secretBytes)
	raw := id.String() + "." + secret
	h := sha256.Sum256(secretBytes)

	return &Token{
		ID:     id,
		Secret: secret,
		Raw:    raw,
		Hash:   h[:],
	}, nil
}

// Parse splits the raw "<id>.<secret>" string and recomputes the hash.
func Parse(raw string) (*Token, error) {
	// Find the first dot separator.
	dotIdx := -1
	for i, b := range raw {
		if b == '.' {
			dotIdx = i
			break
		}
	}

	if dotIdx < 0 {
		return nil, fmt.Errorf("invalid refresh token format")
	}

	idStr := raw[:dotIdx]
	secret := raw[dotIdx+1:]

	id, err := uuid.Parse(idStr)
	if err != nil {
		return nil, fmt.Errorf("invalid refresh token id: %w", err)
	}

	secretBytes, err := base64.RawURLEncoding.DecodeString(secret)
	if err != nil {
		return nil, fmt.Errorf("invalid refresh token secret: %w", err)
	}

	h := sha256.Sum256(secretBytes)

	return &Token{
		ID:     id,
		Secret: secret,
		Raw:    raw,
		Hash:   h[:],
	}, nil
}
