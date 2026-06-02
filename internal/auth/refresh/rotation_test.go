package refresh_test

import (
	"strings"
	"testing"

	"github.com/CoverOnes/user/internal/auth/refresh"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerate_Format(t *testing.T) {
	tok, err := refresh.Generate()
	require.NoError(t, err)
	assert.NotEmpty(t, tok.ID)
	assert.NotEmpty(t, tok.Secret)
	assert.NotEmpty(t, tok.Raw)
	assert.Len(t, tok.Hash, 32) // SHA-256 always 32 bytes

	// Raw must be "<uuid>.<secret>"
	parts := strings.SplitN(tok.Raw, ".", 2)
	require.Len(t, parts, 2)
	assert.Equal(t, tok.ID.String(), parts[0])
}

func TestGenerate_UniqueEachTime(t *testing.T) {
	tok1, err := refresh.Generate()
	require.NoError(t, err)

	tok2, err := refresh.Generate()
	require.NoError(t, err)

	assert.NotEqual(t, tok1.ID, tok2.ID)
	assert.NotEqual(t, tok1.Raw, tok2.Raw)
	assert.NotEqual(t, tok1.Hash, tok2.Hash)
}

func TestParse_HappyPath(t *testing.T) {
	tok, err := refresh.Generate()
	require.NoError(t, err)

	parsed, err := refresh.Parse(tok.Raw)
	require.NoError(t, err)
	assert.Equal(t, tok.ID, parsed.ID)
	assert.Equal(t, tok.Hash, parsed.Hash, "hash must match after round-trip")
}

func TestParse_InvalidFormat_NoDot(t *testing.T) {
	_, err := refresh.Parse("nodotinthisstring")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "format")
}

func TestParse_InvalidUUID(t *testing.T) {
	_, err := refresh.Parse("not-a-uuid.secretpart")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "id")
}

func TestParse_InvalidBase64Secret(t *testing.T) {
	_, err := refresh.Parse("550e8400-e29b-41d4-a716-446655440000.!!!invalid!!!")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "secret")
}

func TestParse_TamperedSecret_DifferentHash(t *testing.T) {
	tok, err := refresh.Generate()
	require.NoError(t, err)

	// Generate another token; parse with original ID but different secret.
	tok2, err := refresh.Generate()
	require.NoError(t, err)

	tampered := tok.ID.String() + "." + tok2.Secret

	parsed, err := refresh.Parse(tampered)
	require.NoError(t, err)

	// Hashes must differ.
	assert.NotEqual(t, tok.Hash, parsed.Hash)
}
