package handler

import (
	"net/http"

	"github.com/CoverOnes/user/internal/auth/jwt"
	"github.com/gin-gonic/gin"
)

// JWKSHandler handles GET /jwks.
type JWKSHandler struct {
	signer *jwt.Signer
}

// NewJWKSHandler returns a JWKSHandler.
func NewJWKSHandler(signer *jwt.Signer) *JWKSHandler {
	return &JWKSHandler{signer: signer}
}

// Get handles GET /jwks — returns the Ed25519 public key set.
// Cache-Control: public, max-age=300 allows downstream caching.
func (h *JWKSHandler) Get(c *gin.Context) {
	c.Header("Cache-Control", "public, max-age=300")
	c.JSON(http.StatusOK, h.signer.BuildJWKS())
}
