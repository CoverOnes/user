package middleware

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testSecret is a 32-char placeholder HMAC secret used in tests only — not a real secret.
const testSecret = "0123456789abcdef0123456789abcdef"

// Fixed identity values shared across the table.
const (
	fixUserID        = "11111111-1111-1111-1111-111111111111"
	fixRealTier      = "2"
	fixAccountType   = "PERSONAL"
	fixEmailVerified = "true"
	fixRequestID     = "req-abc"
)

// signCanonical is an INDEPENDENT reimplementation of the §24.1 rev2-B canonical string
// and HMAC, used by the tests to build a valid signature. It deliberately does
// NOT call the production computeGatewaySignature — using its OWN hmac.New keeps
// the "valid → pass" test from being a tautology (it proves the production code
// agrees with an independently-derived expected value).
//
// Format (length-prefix framing):
//
//	{len(method)}\n{method}\n{len(path)}\n{path}\n{len(bodyHashHex)}\n{bodyHashHex}\n{identity|pipe|delimited|ts}
func signCanonical(t *testing.T, secret, method, path, accountType, ts string, body []byte) string {
	t.Helper()

	bodyHashRaw := sha256.Sum256(body)
	bodyHashHex := hex.EncodeToString(bodyHashRaw[:])

	canonical := fmt.Sprintf(
		"%d\n%s\n%d\n%s\n%d\n%s\n%s",
		len(method), method,
		len(path), path,
		len(bodyHashHex), bodyHashHex,
		strings.Join([]string{
			fixUserID, fixRealTier, accountType, fixEmailVerified, fixRequestID, ts,
		}, "|"),
	)

	mac := hmac.New(sha256.New, []byte(secret))
	_, err := mac.Write([]byte(canonical))
	require.NoError(t, err)

	return hex.EncodeToString(mac.Sum(nil))
}

// newSignedRequest builds a request carrying the six identity headers plus a
// gateway timestamp and signature computed over them + the method/path/body.
// headerKYCTier carries the honest fixRealTier the signature is computed over;
// tamper tests override headers after construction.
func newSignedRequest(
	t *testing.T,
	secret, accountType string,
	ts int64,
	method, path string,
	body []byte,
) *http.Request {
	t.Helper()

	tsStr := strconv.FormatInt(ts, 10)
	sig := signCanonical(t, secret, method, path, accountType, tsStr, body)

	var reqBody *bytes.Reader
	if len(body) > 0 {
		reqBody = bytes.NewReader(body)
	} else {
		reqBody = bytes.NewReader(nil)
	}

	req := httptest.NewRequestWithContext(
		t.Context(),
		method,
		path,
		reqBody,
	)
	req.Header.Set(headerUserID, fixUserID)
	req.Header.Set(headerKYCTier, fixRealTier)
	req.Header.Set(headerAccountType, accountType)
	req.Header.Set(headerEmailVerified, fixEmailVerified)
	req.Header.Set(headerRequestID, fixRequestID)
	req.Header.Set(headerGatewayTs, tsStr)
	req.Header.Set(headerGatewaySignature, sig)

	return req
}

// runWithMiddleware wires VerifyGatewaySignature(secret, rdb) onto a single protected
// route whose handler returns 200, then serves req and returns the recorder.
func runWithMiddleware(secret string, rdb *redis.Client, req *http.Request) *httptest.ResponseRecorder {
	gin.SetMode(gin.TestMode)

	r := gin.New()
	r.Use(VerifyGatewaySignature(secret, rdb))
	r.Any("/*path", func(c *gin.Context) { c.Status(http.StatusOK) })

	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	return rec
}

func TestVerifyGatewaySignature(t *testing.T) {
	now := time.Now().Unix()

	t.Run("valid GET signature passes", func(t *testing.T) {
		req := newSignedRequest(t, testSecret, fixAccountType, now, http.MethodGet, "/protected", nil)

		rec := runWithMiddleware(testSecret, nil, req)

		assert.Equal(t, http.StatusOK, rec.Code, "a correctly-signed GET request must pass")
	})

	t.Run("valid POST with body signature passes", func(t *testing.T) {
		body := []byte(`{"title":"test"}`)
		req := newSignedRequest(t, testSecret, fixAccountType, now, http.MethodPost, "/v1/me/profile", body)

		rec := runWithMiddleware(testSecret, nil, req)

		assert.Equal(t, http.StatusOK, rec.Code, "a correctly-signed POST with body must pass")
	})

	t.Run("body replay: same body on different path is rejected", func(t *testing.T) {
		// A signature over POST /v1/me must NOT verify on POST /v1/me/profile,
		// because the path is included in the canonical string.
		body := []byte(`{"amount":100}`)
		reqA := newSignedRequest(t, testSecret, fixAccountType, now, http.MethodPost, "/v1/me", body)
		// Grab the signature computed for /v1/me and apply it to /v1/me/profile.
		sig := reqA.Header.Get(headerGatewaySignature)

		reqB := newSignedRequest(t, testSecret, fixAccountType, now, http.MethodPost, "/v1/me/profile", body)
		reqB.Header.Set(headerGatewaySignature, sig) // cross-endpoint replay

		rec := runWithMiddleware(testSecret, nil, reqB)

		assert.Equal(t, http.StatusUnauthorized, rec.Code,
			"cross-endpoint replay with same body must be rejected (path bound in canonical)")
	})

	t.Run("method swap replay: GET sig on POST is rejected", func(t *testing.T) {
		// Signature over GET /protected must NOT verify as POST /protected.
		reqGet := newSignedRequest(t, testSecret, fixAccountType, now, http.MethodGet, "/protected", nil)
		sig := reqGet.Header.Get(headerGatewaySignature)

		reqPost := newSignedRequest(t, testSecret, fixAccountType, now, http.MethodPost, "/protected", nil)
		reqPost.Header.Set(headerGatewaySignature, sig) // method swap replay

		rec := runWithMiddleware(testSecret, nil, reqPost)

		assert.Equal(t, http.StatusUnauthorized, rec.Code,
			"method-swap replay must be rejected (method bound in canonical)")
	})

	t.Run("body tampering: valid sig but different body is rejected", func(t *testing.T) {
		body := []byte(`{"title":"original"}`)
		req := newSignedRequest(t, testSecret, fixAccountType, now, http.MethodPost, "/v1/me/profile", body)
		// Replace body with tampered content after signing.
		req.Body = io.NopCloser(bytes.NewReader([]byte(`{"title":"tampered"}`)))

		rec := runWithMiddleware(testSecret, nil, req)

		assert.Equal(t, http.StatusUnauthorized, rec.Code,
			"tampered body must be rejected (body hash bound in canonical)")
	})

	t.Run("missing signature is rejected 401", func(t *testing.T) {
		req := newSignedRequest(t, testSecret, fixAccountType, now, http.MethodGet, "/protected", nil)
		req.Header.Del(headerGatewaySignature)

		rec := runWithMiddleware(testSecret, nil, req)

		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	})

	t.Run("missing timestamp is rejected 401", func(t *testing.T) {
		req := newSignedRequest(t, testSecret, fixAccountType, now, http.MethodGet, "/protected", nil)
		req.Header.Del(headerGatewayTs)

		rec := runWithMiddleware(testSecret, nil, req)

		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	})

	t.Run("tampered signature is rejected 401", func(t *testing.T) {
		req := newSignedRequest(t, testSecret, fixAccountType, now, http.MethodGet, "/protected", nil)
		// Flip the signature to a valid-hex but wrong digest.
		req.Header.Set(headerGatewaySignature, strings.Repeat("a", 64))

		rec := runWithMiddleware(testSecret, nil, req)

		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	})

	t.Run("non-hex signature is rejected 401", func(t *testing.T) {
		req := newSignedRequest(t, testSecret, fixAccountType, now, http.MethodGet, "/protected", nil)
		req.Header.Set(headerGatewaySignature, "not-hex-zzzz")

		rec := runWithMiddleware(testSecret, nil, req)

		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	})

	t.Run("stale timestamp beyond skew is rejected 401", func(t *testing.T) {
		stale := now - int64(maxGatewaySkew.Seconds()) - 5
		req := newSignedRequest(t, testSecret, fixAccountType, stale, http.MethodGet, "/protected", nil)

		rec := runWithMiddleware(testSecret, nil, req)

		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	})

	t.Run("future timestamp beyond skew is rejected 401", func(t *testing.T) {
		future := now + int64(maxGatewaySkew.Seconds()) + 5
		req := newSignedRequest(t, testSecret, fixAccountType, future, http.MethodGet, "/protected", nil)

		rec := runWithMiddleware(testSecret, nil, req)

		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	})

	t.Run("non-numeric timestamp is rejected 401", func(t *testing.T) {
		req := newSignedRequest(t, testSecret, fixAccountType, now, http.MethodGet, "/protected", nil)
		req.Header.Set(headerGatewayTs, "not-a-number")

		rec := runWithMiddleware(testSecret, nil, req)

		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	})

	t.Run("forged kyc tier with signature over real tier is rejected 401", func(t *testing.T) {
		// Attacker signs over the REAL tier (2) but then forges X-Kyc-Tier=3 on
		// the wire. The recomputed canonical uses the forged header (3), so the
		// signature no longer matches → 401. This is the core threat §24.1 closes.
		req := newSignedRequest(t, testSecret, fixAccountType, now, http.MethodGet, "/protected", nil)
		req.Header.Set(headerKYCTier, "3") // forged: claims Tier-3 over a Tier-2 signature

		rec := runWithMiddleware(testSecret, nil, req)

		assert.Equal(t, http.StatusUnauthorized, rec.Code, "forged tier must not pass")
	})

	t.Run("empty account type keeps stable pipe positions and still passes", func(t *testing.T) {
		// §24.1 empty-field rule: an empty value is an empty field. A request
		// signed with accountType="" must verify when accountType is sent empty.
		req := newSignedRequest(t, testSecret, "", now, http.MethodGet, "/protected", nil)

		rec := runWithMiddleware(testSecret, nil, req)

		assert.Equal(t, http.StatusOK, rec.Code, "empty account type must still verify (stable | positions)")
	})

	t.Run("dev with empty secret skips verification", func(t *testing.T) {
		// Dev posture: no secret → middleware is a passthrough. An unsigned
		// request (no X-Gateway-* headers) must pass through to the handler.
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/protected", http.NoBody)
		req.Header.Set(headerUserID, fixUserID)

		rec := runWithMiddleware("", nil, req)

		assert.Equal(t, http.StatusOK, rec.Code, "dev-no-secret must skip verification")
	})

	t.Run("wrong secret is rejected 401", func(t *testing.T) {
		// Signed with a different secret than the verifier holds → mismatch.
		req := newSignedRequest(t, "ffffffffffffffffffffffffffffffff", fixAccountType, now, http.MethodGet, "/protected", nil)

		rec := runWithMiddleware(testSecret, nil, req)

		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	})
}

// TestVerifyGatewaySignature_NonceReplay tests the Redis-backed nonce replay prevention.
// It uses miniredis (in-process Redis) so no external Redis is needed.
func TestVerifyGatewaySignature_NonceReplay(t *testing.T) {
	t.Run("storeNonce returns true on first call and false on second (same requestId)", func(t *testing.T) {
		// Spin up an in-process miniredis server; no external Redis required.
		mr := miniredis.RunT(t)

		rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
		defer rdb.Close() //nolint:errcheck // test teardown

		ctx := context.Background()
		nonce := "test-sig-ts-nonce-abc123"

		// First call: key does not exist → SET NX succeeds → return true (fresh).
		first := storeNonce(ctx, rdb, nonce)
		require.True(t, first, "first storeNonce call must return true (key newly set)")

		// Second call: key already exists → SET NX is a no-op → return false (replay).
		second := storeNonce(ctx, rdb, nonce)
		assert.False(t, second, "second storeNonce call with same nonce must return false (replay detected)")
	})

	t.Run("nil redis client skips nonce check", func(t *testing.T) {
		// When rdb is nil, replay check is skipped; same requestId should pass twice.
		now := time.Now().Unix()

		req1 := newSignedRequest(t, testSecret, fixAccountType, now, http.MethodGet, "/protected", nil)
		req2 := newSignedRequest(t, testSecret, fixAccountType, now, http.MethodGet, "/protected", nil)

		// Same requestId (fixRequestID) both signed at the same ts.
		rec1 := runWithMiddleware(testSecret, nil, req1)
		rec2 := runWithMiddleware(testSecret, nil, req2)

		assert.Equal(t, http.StatusOK, rec1.Code, "first request must pass without Redis")
		assert.Equal(t, http.StatusOK, rec2.Code, "second request must also pass without Redis (nonce check skipped)")
	})

	t.Run("storeNonce rejects when Redis errors", func(t *testing.T) {
		// Dial a Redis client to an address that will always fail (bad port).
		badRDB := redis.NewClient(&redis.Options{
			Addr:         "127.0.0.1:1", // no server here
			DialTimeout:  5 * time.Millisecond,
			ReadTimeout:  5 * time.Millisecond,
			WriteTimeout: 5 * time.Millisecond,
		})
		defer badRDB.Close() //nolint:errcheck // test teardown

		ok := storeNonce(context.Background(), badRDB, "test-nonce-bad-redis")
		assert.False(t, ok, "storeNonce must return false (reject) on Redis error (fail-closed)")
	})

	t.Run("fail-closed: valid signature + bad Redis → 401 (replay check fail-closed)", func(t *testing.T) {
		// When Redis is configured but unreachable, VerifyGatewaySignature must
		// reject the request (fail-closed). A valid signature alone is insufficient
		// when nonce storage fails — we prefer availability loss over replay attack.
		now := time.Now().Unix()
		req := newSignedRequest(t, testSecret, fixAccountType, now, http.MethodGet, "/protected", nil)

		badRDB := redis.NewClient(&redis.Options{
			Addr:         "127.0.0.1:1", // no server here
			DialTimeout:  5 * time.Millisecond,
			ReadTimeout:  5 * time.Millisecond,
			WriteTimeout: 5 * time.Millisecond,
		})
		defer badRDB.Close() //nolint:errcheck // test teardown

		// runWithMiddleware receives a non-nil badRDB — exercises the non-nil path.
		rec := runWithMiddleware(testSecret, badRDB, req)
		assert.Equal(t, http.StatusUnauthorized, rec.Code,
			"valid signature must be rejected when Redis nonce storage fails (fail-closed)")
	})

	t.Run("replay of same requestId within skew window with Redis is rejected", func(t *testing.T) {
		mr := miniredis.RunT(t)
		rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
		defer rdb.Close() //nolint:errcheck // test teardown

		now := time.Now().Unix()
		req1 := newSignedRequest(t, testSecret, fixAccountType, now, http.MethodGet, "/protected", nil)

		// Build a second request with the same requestId.
		req2 := newSignedRequest(t, testSecret, fixAccountType, now, http.MethodGet, "/protected", nil)
		// req2 has the same fixRequestID — same nonce as req1.

		rec1 := runWithMiddleware(testSecret, rdb, req1)
		rec2 := runWithMiddleware(testSecret, rdb, req2)

		assert.Equal(t, http.StatusOK, rec1.Code, "first request with unique nonce must pass")
		assert.Equal(t, http.StatusUnauthorized, rec2.Code,
			"second request with same requestId must be rejected as replay (Redis SETNX)")
	})
}
