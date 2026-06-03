package events

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// signFixture computes the contract signature for a fixed input, used to derive a
// known-good signature the table tests can mutate.
//
//nolint:gocritic // hugeParam: value copy is intentional so callers pass struct literals inline
func signFixture(t *testing.T, secret string, in signatureInput) string {
	t.Helper()

	return computeSignature([]byte(secret), &in)
}

func TestVerifySignature(t *testing.T) {
	t.Parallel()

	const secret = "this-is-a-32-byte-test-secret-xx" //nolint:gosec // G101: test fixture secret, not a real credential

	base := signatureInput{
		eventID:    "11111111-1111-1111-1111-111111111111",
		occurredAt: "2026-06-04T12:00:00Z",
		version:    "1",
		userID:     "22222222-2222-2222-2222-222222222222",
		newTier:    "2",
	}
	goodSig := signFixture(t, secret, base)

	tests := []struct {
		name   string
		secret string
		in     signatureInput
		got    string
		want   bool
	}{
		{
			name:   "valid signature accepted",
			secret: secret,
			in:     base,
			got:    goodSig,
			want:   true,
		},
		{
			name:   "missing signature rejected",
			secret: secret,
			in:     base,
			got:    "",
			want:   false,
		},
		{
			name:   "tampered newTier rejected (forged elevation)",
			secret: secret,
			in: signatureInput{
				eventID:    base.eventID,
				occurredAt: base.occurredAt,
				version:    base.version,
				userID:     base.userID,
				newTier:    "2",
			},
			// Signature was computed over newTier "0"; presenting it for "2" must fail.
			got:  signFixture(t, secret, signatureInput{base.eventID, base.occurredAt, base.version, base.userID, "0"}),
			want: false,
		},
		{
			name:   "tampered userID rejected",
			secret: secret,
			in: signatureInput{
				eventID:    base.eventID,
				occurredAt: base.occurredAt,
				version:    base.version,
				userID:     "33333333-3333-3333-3333-333333333333",
				newTier:    base.newTier,
			},
			got:  goodSig, // signed for the original userID
			want: false,
		},
		{
			name:   "wrong secret rejected",
			secret: "a-totally-different-32-byte-secret",
			in:     base,
			got:    goodSig, // signed with the original secret
			want:   false,
		},
		{
			name:   "garbage signature rejected",
			secret: secret,
			in:     base,
			got:    "deadbeef",
			want:   false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			in := tc.in
			got := verifySignature([]byte(tc.secret), &in, tc.got)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestCanonical(t *testing.T) {
	t.Parallel()

	in := signatureInput{
		eventID:    "e",
		occurredAt: "o",
		version:    "1",
		userID:     "u",
		newTier:    "2",
	}
	assert.Equal(t, "e|o|1|u|2", in.canonical())
}

func TestUnquoteJSONString(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		raw  string
		want string
	}{
		{name: "quoted RFC3339", raw: `"2026-06-04T12:00:00Z"`, want: "2026-06-04T12:00:00Z"},
		{name: "unquoted passthrough", raw: "123", want: "123"},
		{name: "empty", raw: "", want: ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tc.want, unquoteJSONString(tc.raw))
		})
	}
}
