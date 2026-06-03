package events

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"
)

// EVENT HMAC CONTRACT (shared with the kyc publisher — keep both sides in sync).
//
// For a kyc.tier_changed envelope:
//
//	{ "eventId", "occurredAt", "version", "data": { "userId", "oldTier", "newTier" }, "signature" }
//
// the canonical string is:
//
//	eventId + "|" + occurredAt + "|" + version + "|" + userId + "|" + newTier
//
// and the signature is the lowercase hex of HMAC-SHA256(EVENT_HMAC_SECRET, canonical).
//
// The consumer recomputes the signature from the RECEIVED fields (using the exact
// textual form that was transmitted on the wire for occurredAt — see signatureInput)
// and compares it with hmac.Equal (constant-time). On mismatch or a missing
// signature the event is dropped; the tier change is NOT applied.

// signatureInput carries the verbatim textual values used to rebuild the canonical
// signing string. occurredAt is captured from the raw wire bytes (quotes stripped)
// so the consumer and publisher agree byte-for-byte regardless of how either side
// formats RFC3339 timestamps.
type signatureInput struct {
	eventID    string
	occurredAt string
	version    string
	userID     string
	newTier    string
}

// canonical builds the pipe-delimited canonical string defined by the HMAC contract.
func (s *signatureInput) canonical() string {
	return strings.Join(
		[]string{s.eventID, s.occurredAt, s.version, s.userID, s.newTier},
		"|",
	)
}

// computeSignature returns the lowercase-hex HMAC-SHA256 of the canonical string.
func computeSignature(secret []byte, in *signatureInput) string {
	mac := hmac.New(sha256.New, secret)
	// hash.Hash.Write never returns an error (documented), so the result is ignored.
	_, _ = mac.Write([]byte(in.canonical()))

	return hex.EncodeToString(mac.Sum(nil))
}

// verifySignature reports whether got matches the expected signature for in.
// The comparison is constant-time (hmac.Equal) to avoid leaking timing information.
// A missing (empty) signature is always rejected.
func verifySignature(secret []byte, in *signatureInput, got string) bool {
	if got == "" {
		return false
	}

	want := computeSignature(secret, in)

	return hmac.Equal([]byte(want), []byte(got))
}

// unquoteJSONString strips one layer of surrounding double quotes from a raw JSON
// token. occurredAt arrives as a quoted RFC3339 string ("2026-06-04T12:00:00Z");
// the canonical contract signs the unquoted value. If the token is not a quoted
// string it is returned unchanged.
func unquoteJSONString(raw string) string {
	if unquoted, err := strconv.Unquote(raw); err == nil {
		return unquoted
	}

	return raw
}
