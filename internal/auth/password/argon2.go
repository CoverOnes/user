// Package password provides Argon2id password hashing and verification.
package password

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Params defines the Argon2id parameters.
type Params struct {
	Memory      uint32 // in KiB
	Iterations  uint32
	Parallelism uint8
	SaltLen     uint32
	KeyLen      uint32
}

// DefaultParams are the production Argon2id parameters per spec §7.2.
var DefaultParams = Params{
	Memory:      64 * 1024, // 64 MB
	Iterations:  3,
	Parallelism: 2,
	SaltLen:     16,
	KeyLen:      32,
}

// Hash derives an Argon2id hash from plaintext and returns the encoded string.
// Format: $argon2id$v=19$m=<mem>,t=<iter>,p=<par>$<salt>$<key>
func Hash(plaintext string, params Params) (string, error) {
	salt := make([]byte, params.SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generate salt: %w", err)
	}

	key := argon2.IDKey([]byte(plaintext), salt, params.Iterations, params.Memory, params.Parallelism, params.KeyLen)

	encoded := fmt.Sprintf(
		"$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		params.Memory,
		params.Iterations,
		params.Parallelism,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key),
	)

	return encoded, nil
}

// Verify returns true if the plaintext matches the stored Argon2id hash.
// Uses constant-time comparison to prevent timing attacks.
func Verify(plaintext, encoded string) (bool, error) {
	p, salt, key, err := decode(encoded)
	if err != nil {
		return false, err
	}

	derived := argon2.IDKey([]byte(plaintext), salt, p.Iterations, p.Memory, p.Parallelism, p.KeyLen)

	return subtle.ConstantTimeCompare(key, derived) == 1, nil
}

// decode parses the encoded Argon2id hash string back into its components.
func decode(encoded string) (Params, []byte, []byte, error) { //nolint:gocritic // unnamedResult: named returns shadow inner := declarations
	parts := strings.Split(encoded, "$")
	// Expected format: ["", "argon2id", "v=19", "m=...,t=...,p=...", "<salt>", "<key>"]
	if len(parts) != 6 {
		return Params{}, nil, nil, errors.New("invalid argon2id hash format")
	}

	if parts[1] != "argon2id" {
		return Params{}, nil, nil, errors.New("unsupported argon2 variant")
	}

	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return Params{}, nil, nil, fmt.Errorf("parse version: %w", err)
	}

	if version != argon2.Version {
		return Params{}, nil, nil, fmt.Errorf("unsupported argon2 version: %d", version)
	}

	var p Params
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &p.Memory, &p.Iterations, &p.Parallelism); err != nil {
		return Params{}, nil, nil, fmt.Errorf("parse params: %w", err)
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return Params{}, nil, nil, fmt.Errorf("decode salt: %w", err)
	}

	key, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return Params{}, nil, nil, fmt.Errorf("decode key: %w", err)
	}

	p.SaltLen = uint32(len(salt))
	p.KeyLen = uint32(len(key))

	return p, salt, key, nil
}

// MeetsComplexity returns an error if the password does not meet minimum requirements.
// Min 12 chars. Future: HIBP check is deferred.
func MeetsComplexity(pw string) error {
	if len([]rune(pw)) < 12 {
		return fmt.Errorf("password must be at least 12 characters")
	}

	return nil
}
