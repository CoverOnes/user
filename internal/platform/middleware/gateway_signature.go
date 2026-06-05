package middleware

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/CoverOnes/user/internal/platform/httpx"
	"github.com/gin-gonic/gin"
)

const (
	headerUserID           = "X-User-Id"
	headerKYCTier          = "X-Kyc-Tier"
	headerAccountType      = "X-Account-Type"
	headerEmailVerified    = "X-Email-Verified"
	headerGatewayTs        = "X-Gateway-Ts"
	headerGatewaySignature = "X-Gateway-Signature"

	// maxGatewaySkew bounds the replay window: a signed request is rejected when
	// |now - X-Gateway-Ts| exceeds this. Locked by conventions §24.1.
	maxGatewaySkew = 30 * time.Second
)

// VerifyGatewaySignature returns a middleware that proves the request actually
// originated from the API gateway, by verifying the HMAC-SHA256 signature the
// gateway emits over the identity tuple (conventions §24.1). It MUST be registered
// BEFORE any auth middleware (JWT or identity-header) on the protected group.
//
// This is defense-in-depth: even though the user service primarily relies on Bearer
// JWT verification, the gateway signature ensures only gateway-forwarded requests
// reach protected routes — a forged request that bypasses the gateway is rejected
// before any JWT or identity-header logic executes.
//
// When secret == "" (development only — the gateway also disables signing in dev)
// verification is skipped and the request passes through unchanged. In non-dev
// environments config validation guarantees a non-empty secret, so this branch
// is never reached in staging/production.
func VerifyGatewaySignature(secret string) gin.HandlerFunc {
	if secret == "" {
		// Dev posture: signing disabled gateway-side, verification disabled here.
		return func(c *gin.Context) { c.Next() }
	}

	secretBytes := []byte(secret)

	return func(c *gin.Context) {
		sig := c.GetHeader(headerGatewaySignature)
		ts := c.GetHeader(headerGatewayTs)

		// Unsigned request → never trust identity headers on a protected route.
		if sig == "" || ts == "" {
			rejectUnauthorized(c)
			return
		}

		tsInt, err := strconv.ParseInt(ts, 10, 64)
		if err != nil || !withinSkew(tsInt) {
			rejectUnauthorized(c)
			return
		}

		expected := computeGatewaySignature(secretBytes, c, ts)

		// hex-decode both sides and compare in constant time (hmac.Equal).
		// A non-hex incoming signature decodes with error → treated as mismatch.
		sigBytes, decodeErr := hex.DecodeString(sig)
		if decodeErr != nil || !hmac.Equal(sigBytes, expected) {
			rejectUnauthorized(c)
			return
		}

		c.Next()
	}
}

// computeGatewaySignature builds the §24.1 canonical string from the request's
// header values (empty value → empty field, stable '|' positions) and returns the
// raw HMAC-SHA256 digest bytes (not hex-encoded).
func computeGatewaySignature(secret []byte, c *gin.Context, ts string) []byte {
	canonical := strings.Join([]string{
		c.GetHeader(headerUserID),
		c.GetHeader(headerKYCTier),
		c.GetHeader(headerAccountType),
		c.GetHeader(headerEmailVerified),
		c.GetHeader(headerRequestID),
		ts,
	}, "|")

	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(canonical)) // hash.Hash.Write never returns an error

	return mac.Sum(nil)
}

// withinSkew reports whether the gateway timestamp is within the allowed replay
// window of the current time.
func withinSkew(tsUnix int64) bool {
	delta := time.Since(time.Unix(tsUnix, 0))
	if delta < 0 {
		delta = -delta
	}

	return delta <= maxGatewaySkew
}

// rejectUnauthorized aborts with a generic 401 that does not leak which check
// failed (missing header vs skew vs signature mismatch all look identical).
func rejectUnauthorized(c *gin.Context) {
	c.Abort()
	httpx.ErrCode(c, http.StatusUnauthorized, "UNAUTHORIZED", "authentication required")
}
