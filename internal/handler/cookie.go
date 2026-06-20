package handler

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// Refresh-token cookie attributes.
//
// The refresh token is delivered to the browser as an HttpOnly cookie instead of
// in the JSON response body so that JS (and therefore an XSS payload) can never
// read it. The cookie is narrowly path-scoped to /v1/auth so it is only ever sent
// on the refresh/logout endpoints, never on /api/*, /v1/me/*, etc.
const (
	// refreshCookieName is the public cookie NAME carrying the refresh token (not a
	// secret value).
	refreshCookieName = "refresh_token"
	// refreshCookiePath scopes the cookie so the browser only attaches it to
	// /v1/auth/* requests (refresh + logout), never to other API surfaces.
	refreshCookiePath = "/v1/auth"
)

// setRefreshCookie writes the refresh-token cookie on the response.
//
// Security posture (see SPEC §13):
//   - HttpOnly: JS cannot read the token (XSS-resistant).
//   - Secure: always set — the browser silently ignores it on http://localhost,
//     so it is harmless in dev and mandatory in prod.
//   - SameSite=Strict: the refresh endpoint is only ever called by same-origin JS
//     (POST /v1/auth/refresh), never via a cross-site navigation.
//   - Path=/v1/auth: the cookie is not sent on /api/*, /v1/me/*, etc.
//   - Domain: empty string omits the Domain attribute, scoping the cookie to the
//     request host (correct for dev). In prod set USER_REFRESH_TOKEN_COOKIE_DOMAIN
//     to the apex domain (e.g. "coverones.com").
//
// maxAgeSec is the cookie lifetime in seconds (RefreshTokenTTLHours * 3600).
func setRefreshCookie(c *gin.Context, token string, maxAgeSec int, domain string) {
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     refreshCookieName,
		Value:    token,
		Path:     refreshCookiePath,
		Domain:   domain,
		MaxAge:   maxAgeSec,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})
}

// clearRefreshCookie expires the refresh-token cookie (logout). It MUST mirror the
// Path/Domain/security attributes of setRefreshCookie exactly; otherwise the
// browser treats it as a different cookie and does not delete the original.
// MaxAge < 0 instructs the browser to delete the cookie immediately.
func clearRefreshCookie(c *gin.Context, domain string) {
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     refreshCookieName,
		Value:    "",
		Path:     refreshCookiePath,
		Domain:   domain,
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})
}
