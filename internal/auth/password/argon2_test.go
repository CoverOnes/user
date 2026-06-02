package password_test

import (
	"strings"
	"testing"

	"github.com/CoverOnes/user/internal/auth/password"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Use faster params to keep tests quick.
var testParams = password.Params{
	Memory:      16 * 1024,
	Iterations:  1,
	Parallelism: 1,
	SaltLen:     16,
	KeyLen:      32,
}

func TestHash_AndVerify_HappyPath(t *testing.T) {
	plaintext := "correct-horse-battery-staple"
	hash, err := password.Hash(plaintext, testParams)
	require.NoError(t, err)

	assert.True(t, strings.HasPrefix(hash, "$argon2id$"), "hash must be argon2id encoded")

	ok, err := password.Verify(plaintext, hash)
	require.NoError(t, err)
	assert.True(t, ok, "correct plaintext must verify")
}

func TestVerify_WrongPassword(t *testing.T) {
	hash, err := password.Hash("correct-horse-battery-staple", testParams)
	require.NoError(t, err)

	ok, err := password.Verify("wrong-password-totally", hash)
	require.NoError(t, err)
	assert.False(t, ok, "wrong plaintext must not verify")
}

func TestVerify_TamperedHash(t *testing.T) {
	hash, err := password.Hash("correct-horse-battery-staple", testParams)
	require.NoError(t, err)

	// Tamper the key portion.
	tampered := hash[:len(hash)-5] + "XXXXX"

	ok, err := password.Verify("correct-horse-battery-staple", tampered)
	// May error if base64 invalid, or succeed with false — both are acceptable.
	if err == nil {
		assert.False(t, ok, "tampered hash must not verify")
	}
}

func TestVerify_InvalidFormat(t *testing.T) {
	_, err := password.Verify("password", "not-a-valid-hash")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid argon2id hash format")
}

func TestVerify_UniqueHashes(t *testing.T) {
	plaintext := "same-password-12345"

	hash1, err := password.Hash(plaintext, testParams)
	require.NoError(t, err)

	hash2, err := password.Hash(plaintext, testParams)
	require.NoError(t, err)

	// Salts must be different so hashes differ.
	assert.NotEqual(t, hash1, hash2, "two hashes of the same plaintext must differ (different salts)")
}

func TestMeetsComplexity_TooShort(t *testing.T) {
	err := password.MeetsComplexity("short")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "12 characters")
}

func TestMeetsComplexity_ExactlyMinLength(t *testing.T) {
	err := password.MeetsComplexity("exactly12chr")
	require.NoError(t, err)
}

func TestMeetsComplexity_LongPassword(t *testing.T) {
	err := password.MeetsComplexity(strings.Repeat("a", 100))
	require.NoError(t, err)
}
