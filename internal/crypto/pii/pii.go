// Package pii provides authenticated symmetric encryption for HIGH-sensitivity
// personally-identifiable information (legal name, national ID) stored at rest.
//
// Algorithm: AES-256-GCM (stdlib crypto/aes + crypto/cipher, no third-party dep).
// Stored ciphertext layout (the single bytea written to the DB):
//
//	nonce(12 bytes) || ciphertext || GCM tag(16 bytes)
//
// A fresh random 12-byte nonce is drawn per Encrypt call (crypto/rand), so two
// encryptions of the same plaintext yield different ciphertext and the nonce is
// never reused under one key (GCM's hard requirement).
package pii

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
)

// KeySize is the required AES-256 key length in bytes.
const KeySize = 32

// nonceSize is the standard GCM nonce length (12 bytes / 96 bits).
const nonceSize = 12

// ErrInvalidKeySize is returned when the supplied key is not exactly 32 bytes.
var ErrInvalidKeySize = errors.New("pii: encryption key must be exactly 32 bytes")

// ErrCiphertextTooShort is returned when a ciphertext is shorter than the
// minimum framing (nonce + tag), i.e. it cannot possibly be a valid value.
var ErrCiphertextTooShort = errors.New("pii: ciphertext too short")

// Encryptor performs AES-256-GCM encrypt/decrypt of PII values.
// It is safe for concurrent use: cipher.AEAD is stateless and the nonce is
// generated per call.
type Encryptor struct {
	aead cipher.AEAD
}

// NewEncryptor builds an Encryptor from a 32-byte AES-256 key.
// The key MUST be exactly 32 bytes; any other length is rejected at construction
// (callers decode it from base64 and validate the length at boot).
func NewEncryptor(key []byte) (*Encryptor, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("%w: got %d", ErrInvalidKeySize, len(key))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		// Unreachable for a 32-byte key, but never panic on key material.
		return nil, fmt.Errorf("pii: new cipher: %w", err)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("pii: new gcm: %w", err)
	}

	return &Encryptor{aead: aead}, nil
}

// Encrypt returns nonce||ciphertext||tag for the given plaintext.
// The returned error NEVER contains the plaintext.
func (e *Encryptor) Encrypt(plaintext string) ([]byte, error) {
	nonce := make([]byte, nonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("pii: read nonce: %w", err)
	}

	// Seal appends the ciphertext+tag to the nonce prefix in one allocation, so
	// the result is nonce || ciphertext || tag.
	sealed := e.aead.Seal(nonce, nonce, []byte(plaintext), nil)

	return sealed, nil
}

// Decrypt reverses Encrypt. It returns ErrCiphertextTooShort for malformed input
// and a generic decrypt error (NEVER containing plaintext) on authentication
// failure (wrong key / tampered ciphertext).
func (e *Encryptor) Decrypt(data []byte) (string, error) {
	if len(data) < nonceSize+e.aead.Overhead() {
		return "", ErrCiphertextTooShort
	}

	nonce := data[:nonceSize]
	ciphertext := data[nonceSize:]

	plaintext, err := e.aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		// Do not wrap with ciphertext bytes — keep the error opaque.
		return "", errors.New("pii: decrypt failed")
	}

	return string(plaintext), nil
}
