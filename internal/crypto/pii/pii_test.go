package pii_test

import (
	"crypto/rand"
	"testing"

	"github.com/CoverOnes/user/internal/crypto/pii"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newKey(t *testing.T) []byte {
	t.Helper()

	key := make([]byte, pii.KeySize)
	_, err := rand.Read(key)
	require.NoError(t, err)

	return key
}

func TestNewEncryptor_KeySizeValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		keyLen  int
		wantErr bool
	}{
		{name: "exactly 32 bytes ok", keyLen: 32, wantErr: false},
		{name: "16 bytes rejected", keyLen: 16, wantErr: true},
		{name: "31 bytes rejected", keyLen: 31, wantErr: true},
		{name: "33 bytes rejected", keyLen: 33, wantErr: true},
		{name: "empty rejected", keyLen: 0, wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			enc, err := pii.NewEncryptor(make([]byte, tc.keyLen))
			if tc.wantErr {
				require.ErrorIs(t, err, pii.ErrInvalidKeySize)
				assert.Nil(t, enc)

				return
			}

			require.NoError(t, err)
			assert.NotNil(t, enc)
		})
	}
}

func TestEncryptDecrypt_RoundTrip(t *testing.T) {
	t.Parallel()

	enc, err := pii.NewEncryptor(newKey(t))
	require.NoError(t, err)

	plaintexts := []string{
		"A123456789",
		"王小明",           // multibyte
		"",              // empty string round-trips
		"Owner O'Brien", // punctuation
	}

	for _, pt := range plaintexts {
		ct, encErr := enc.Encrypt(pt)
		require.NoError(t, encErr)
		assert.NotEqual(t, []byte(pt), ct, "ciphertext must not equal plaintext bytes")

		got, decErr := enc.Decrypt(ct)
		require.NoError(t, decErr)
		assert.Equal(t, pt, got)
	}
}

func TestEncrypt_NonceIsRandom(t *testing.T) {
	t.Parallel()

	enc, err := pii.NewEncryptor(newKey(t))
	require.NoError(t, err)

	// Two encryptions of the same plaintext must differ (random nonce per call).
	c1, err := enc.Encrypt("A123456789")
	require.NoError(t, err)
	c2, err := enc.Encrypt("A123456789")
	require.NoError(t, err)

	assert.NotEqual(t, c1, c2, "same plaintext must yield different ciphertext (random nonce)")

	// Both still decrypt to the original.
	got1, err := enc.Decrypt(c1)
	require.NoError(t, err)
	got2, err := enc.Decrypt(c2)
	require.NoError(t, err)
	assert.Equal(t, "A123456789", got1)
	assert.Equal(t, "A123456789", got2)
}

func TestDecrypt_TooShort(t *testing.T) {
	t.Parallel()

	enc, err := pii.NewEncryptor(newKey(t))
	require.NoError(t, err)

	_, err = enc.Decrypt([]byte{0x01, 0x02, 0x03})
	require.ErrorIs(t, err, pii.ErrCiphertextTooShort)
}

func TestDecrypt_TamperedCiphertextFails(t *testing.T) {
	t.Parallel()

	enc, err := pii.NewEncryptor(newKey(t))
	require.NoError(t, err)

	ct, err := enc.Encrypt("A123456789")
	require.NoError(t, err)

	// Flip a bit in the tag/ciphertext region — GCM auth must reject it.
	ct[len(ct)-1] ^= 0xFF

	_, err = enc.Decrypt(ct)
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "A123456789", "decrypt error must never leak plaintext")
}

func TestDecrypt_WrongKeyFails(t *testing.T) {
	t.Parallel()

	enc1, err := pii.NewEncryptor(newKey(t))
	require.NoError(t, err)
	enc2, err := pii.NewEncryptor(newKey(t))
	require.NoError(t, err)

	ct, err := enc1.Encrypt("A123456789")
	require.NoError(t, err)

	// Decrypting with a different key must fail authentication.
	_, err = enc2.Decrypt(ct)
	require.Error(t, err)
}
