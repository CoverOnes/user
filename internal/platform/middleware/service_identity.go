package middleware

import (
	"crypto/subtle"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

// RequireServiceIdentity returns a middleware that enforces S2S bearer-token authentication.
// The caller must present a non-empty X-Service-Token header whose value constant-time-equals
// the provided expectedToken. An empty expectedToken panics at startup (misconfiguration).
//
// Security:
//   - Uses subtle.ConstantTimeCompare to prevent timing side-channels.
//   - Returns 401 without revealing whether the token is wrong vs absent.
//   - Tokens are NEVER logged (only "service authentication required" generic message).
func RequireServiceIdentity(expectedToken string) gin.HandlerFunc {
	if expectedToken == "" {
		panic("middleware: RequireServiceIdentity called with empty expectedToken — route must not be registered when token is absent")
	}

	expected := []byte(expectedToken)

	return func(c *gin.Context) {
		token := strings.TrimSpace(c.GetHeader("X-Service-Token"))
		if subtle.ConstantTimeCompare([]byte(token), expected) != 1 {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": gin.H{
					"code":    "UNAUTHORIZED",
					"message": "service authentication required",
				},
			})
			return
		}

		c.Next()
	}
}
