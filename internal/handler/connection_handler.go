package handler

import (
	"net/http"

	"github.com/CoverOnes/user/internal/platform/httpx"
	"github.com/CoverOnes/user/internal/platform/middleware"
	"github.com/CoverOnes/user/internal/service"
	"github.com/CoverOnes/user/internal/store"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// ConnectionHandler handles the /v1/me/connections surface (P4 Network).
//
// PII-SAFE GUARANTEE: connection cards are built from store.ConnectionWithUser,
// whose projection is an explicit non-PII allowlist (no email/national_id/kyc_tier).
// The handler never serializes a *domain.User, so a new PII column on the user row
// can never leak through a connection list even if added later.
type ConnectionHandler struct {
	connections *service.ConnectionService
}

// NewConnectionHandler returns a ConnectionHandler.
func NewConnectionHandler(connections *service.ConnectionService) *ConnectionHandler {
	return &ConnectionHandler{connections: connections}
}

// callerID extracts the authenticated user id from the verified JWT subject. The
// identity ALWAYS comes from claims.Subject — never from a request body — so a
// client cannot act on behalf of another user. Returns (uuid.Nil, false) and writes
// a 401 envelope when the subject is missing or malformed.
func callerID(c *gin.Context) (uuid.UUID, bool) {
	claims, ok := middleware.ClaimsFromCtx(c)
	if !ok {
		httpx.ErrCode(c, http.StatusUnauthorized, "UNAUTHORIZED", "authentication required")
		return uuid.Nil, false
	}

	id, err := uuid.Parse(claims.Subject)
	if err != nil {
		httpx.ErrCode(c, http.StatusUnauthorized, "UNAUTHORIZED", "invalid token subject")
		return uuid.Nil, false
	}

	return id, true
}

// connectionUser is the PII-safe card for the OTHER party in a connection/invite.
// It is the single source of truth for the exposed field set (explicit allowlist).
// Takes a pointer to avoid copying the (heavy) carrier struct (gocritic hugeParam).
func connectionUser(cu *store.ConnectionWithUser) gin.H {
	return gin.H{
		"userId":      cu.OtherUserID,
		"displayName": cu.DisplayName,
		"handle":      cu.Handle,
		"headline":    cu.Headline,
		"avatarUrl":   cu.AvatarURL,
		"accountType": cu.AccountType,
	}
}

// List handles GET /v1/me/connections → {data:{connections:[...]}}.
// Each item is {id, user, connectedAt, degree:1}. Empty list → {connections:[]}.
func (h *ConnectionHandler) List(c *gin.Context) {
	uid, ok := callerID(c)
	if !ok {
		return
	}

	rows, err := h.connections.ListAccepted(c.Request.Context(), uid)
	if err != nil {
		httpx.Err(c, err)
		return
	}

	connections := make([]gin.H, 0, len(rows))
	for i := range rows {
		cu := &rows[i]
		connections = append(connections, gin.H{
			"id":          cu.ID,
			"user":        connectionUser(cu),
			"connectedAt": cu.Timestamp,
			"degree":      1,
		})
	}

	httpx.OK(c, gin.H{"connections": connections})
}

// ListPending handles GET /v1/me/connections/pending →
// {data:{incoming:[...], outgoing:[...]}}. Each item is {id, user, createdAt}.
func (h *ConnectionHandler) ListPending(c *gin.Context) {
	uid, ok := callerID(c)
	if !ok {
		return
	}

	incoming, outgoing, err := h.connections.ListPending(c.Request.Context(), uid)
	if err != nil {
		httpx.Err(c, err)
		return
	}

	httpx.OK(c, gin.H{
		"incoming": pendingInvites(incoming),
		"outgoing": pendingInvites(outgoing),
	})
}

// pendingInvites maps carrier rows to the {id, user, createdAt} invite shape.
func pendingInvites(rows []store.ConnectionWithUser) []gin.H {
	out := make([]gin.H, 0, len(rows))
	for i := range rows {
		cu := &rows[i]
		out = append(out, gin.H{
			"id":        cu.ID,
			"user":      connectionUser(cu),
			"createdAt": cu.Timestamp,
		})
	}

	return out
}

// sendInviteRequest is the POST /v1/me/connections body. The addressee is identified
// by user id (uuid) only — handle-search UX is deferred (resolved-decision #4).
type sendInviteRequest struct {
	AddresseeUserID string `json:"addresseeUserId" binding:"required"`
}

// Send handles POST /v1/me/connections → 201 {data:{id,status:'pending',addresseeUserId}}.
// Identity (the requester) is the JWT subject; the body carries ONLY the addressee.
func (h *ConnectionHandler) Send(c *gin.Context) {
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxBodyBytes)

	uid, ok := callerID(c)
	if !ok {
		return
	}

	var req sendInviteRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		httpx.ErrCode(c, http.StatusBadRequest, "VALIDATION_ERROR", err.Error())
		return
	}

	addresseeID, err := uuid.Parse(req.AddresseeUserID)
	if err != nil {
		httpx.ErrCode(c, http.StatusBadRequest, "VALIDATION_ERROR", "addresseeUserId must be a valid UUID")
		return
	}

	conn, err := h.connections.SendInvite(c.Request.Context(), uid, addresseeID)
	if err != nil {
		httpx.Err(c, err)
		return
	}

	httpx.Created(c, gin.H{
		"id":              conn.ID,
		"status":          conn.Status,
		"addresseeUserId": conn.AddresseeID,
	})
}

// Accept handles POST /v1/me/connections/:id/accept → 200 {data:{id,status:'accepted'}}.
func (h *ConnectionHandler) Accept(c *gin.Context) {
	uid, id, ok := h.callerAndConnectionID(c)
	if !ok {
		return
	}

	if err := h.connections.Accept(c.Request.Context(), id, uid); err != nil {
		httpx.Err(c, err)
		return
	}

	httpx.OK(c, gin.H{"id": id, "status": "accepted"})
}

// Decline handles PATCH /v1/me/connections/:id/decline → 200 {data:{id,status:'declined'}}.
func (h *ConnectionHandler) Decline(c *gin.Context) {
	uid, id, ok := h.callerAndConnectionID(c)
	if !ok {
		return
	}

	if err := h.connections.Decline(c.Request.Context(), id, uid); err != nil {
		httpx.Err(c, err)
		return
	}

	httpx.OK(c, gin.H{"id": id, "status": "declined"})
}

// callerAndConnectionID resolves both the authenticated caller id and the :id path
// param for the accept/decline handlers. Writes the appropriate error envelope and
// returns ok=false on any failure (401 for identity, 400 for a malformed :id).
func (h *ConnectionHandler) callerAndConnectionID(c *gin.Context) (caller, connID uuid.UUID, ok bool) {
	uid, identityOK := callerID(c)
	if !identityOK {
		return uuid.Nil, uuid.Nil, false
	}

	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		httpx.ErrCode(c, http.StatusBadRequest, "VALIDATION_ERROR", "connection id must be a valid UUID")
		return uuid.Nil, uuid.Nil, false
	}

	return uid, id, true
}
