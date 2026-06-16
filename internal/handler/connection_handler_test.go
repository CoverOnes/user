package handler_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/CoverOnes/user/internal/auth/jwt"
	"github.com/CoverOnes/user/internal/domain"
	"github.com/CoverOnes/user/internal/handler"
	"github.com/CoverOnes/user/internal/platform/middleware"
	"github.com/CoverOnes/user/internal/service"
	"github.com/CoverOnes/user/internal/store"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeConnectionStore is an in-memory ConnectionStore for ConnectionHandler tests.
// The list payloads and per-method errors are injectable so handler-level envelope
// shaping and error mapping can be asserted without a real DB. The guarded-UPDATE /
// partial-unique SQL semantics are covered by the Postgres integration test.
type fakeConnStore struct {
	accepted []store.ConnectionWithUser
	incoming []store.ConnectionWithUser
	outgoing []store.ConnectionWithUser

	createErr  error
	acceptErr  error
	declineErr error
	listErr    error

	created    *domain.Connection
	lastID     uuid.UUID
	lastCaller uuid.UUID
}

func (f *fakeConnStore) Create(_ context.Context, c *domain.Connection) error {
	if f.createErr != nil {
		return f.createErr
	}

	cp := *c
	f.created = &cp

	return nil
}

func (f *fakeConnStore) ListAcceptedForUser(_ context.Context, _ uuid.UUID) ([]store.ConnectionWithUser, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}

	return f.accepted, nil
}

func (f *fakeConnStore) ListPendingForUser(_ context.Context, _ uuid.UUID) (incoming, outgoing []store.ConnectionWithUser, err error) {
	if f.listErr != nil {
		return nil, nil, f.listErr
	}

	return f.incoming, f.outgoing, nil
}

func (f *fakeConnStore) AcceptInvite(_ context.Context, id, addresseeID uuid.UUID) error {
	if f.acceptErr != nil {
		return f.acceptErr
	}

	f.lastID = id
	f.lastCaller = addresseeID

	return nil
}

func (f *fakeConnStore) DeclineInvite(_ context.Context, id, addresseeID uuid.UUID) error {
	if f.declineErr != nil {
		return f.declineErr
	}

	f.lastID = id
	f.lastCaller = addresseeID

	return nil
}

// seedConnHandlerUser inserts a live user directly into the handler-test fakeUserStore.
func seedConnHandlerUser(t *testing.T, users *fakeUserStore, email string) *domain.User {
	t.Helper()

	now := time.Now().UTC()
	u := &domain.User{
		ID:          uuid.New(),
		Email:       email,
		DisplayName: "Handler User",
		AccountType: domain.AccountTypePersonal,
		Status:      domain.UserStatusActive,
		KYCTier:     0,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	require.NoError(t, users.Create(context.Background(), u))

	return u
}

// buildConnectionRouter wires a Gin engine for the /v1/me/connections surface backed
// by a real ConnectionService over the supplied fakes (mirrors router.go: Auth on the
// me group, no RequireTier).
func buildConnectionRouter(t *testing.T, users *fakeUserStore, conns *fakeConnStore) (*gin.Engine, *jwt.Signer) {
	t.Helper()

	signer, err := jwt.NewEphemeralSigner(10 * time.Minute)
	require.NoError(t, err)

	svc := service.NewConnectionService(users, conns)
	connH := handler.NewConnectionHandler(svc)

	r := gin.New()
	r.Use(middleware.Recover())

	me := r.Group("/v1/me")
	me.Use(middleware.Auth(signer))

	group := me.Group("/connections")
	group.GET("", connH.List)
	group.GET("/pending", connH.ListPending)
	group.POST("", connH.Send)
	group.POST("/:id/accept", connH.Accept)
	group.PATCH("/:id/decline", connH.Decline)

	return r, signer
}

func tokenFor(t *testing.T, signer *jwt.Signer, u *domain.User) string {
	t.Helper()

	tok, err := signer.Issue(u.ID.String(), domain.AccountTypePersonal, u.KYCTier, 0, true)
	require.NoError(t, err)

	return tok
}

func doJSON(t *testing.T, r http.Handler, method, path, token string, body any) *httptest.ResponseRecorder {
	t.Helper()

	var rdr *bytes.Buffer
	if body != nil {
		rdr = &bytes.Buffer{}
		require.NoError(t, json.NewEncoder(rdr).Encode(body))
	} else {
		rdr = &bytes.Buffer{}
	}

	req := httptest.NewRequestWithContext(context.Background(), method, path, rdr)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	return w
}

func TestConnectionHandler_List_Envelope(t *testing.T) {
	users := newFakeUserStore()
	me := seedConnHandlerUser(t, users, "me-list@example.com")
	conns := &fakeConnStore{
		accepted: []store.ConnectionWithUser{
			{
				ID:          uuid.New(),
				OtherUserID: uuid.New(),
				DisplayName: "Bob",
				Handle:      strp("bobby"),
				Headline:    strp("Engineer"),
				AvatarURL:   strp("https://cdn.example.com/b.png"),
				AccountType: domain.AccountTypePersonal,
				Timestamp:   time.Now().UTC(),
			},
		},
	}
	r, signer := buildConnectionRouter(t, users, conns)

	w := doJSON(t, r, http.MethodGet, "/v1/me/connections", tokenFor(t, signer, me), nil)
	require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())

	var env struct {
		Data struct {
			Connections []map[string]any `json:"connections"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &env))
	require.Len(t, env.Data.Connections, 1)

	item := env.Data.Connections[0]
	assert.EqualValues(t, 1, item["degree"])
	assert.NotEmpty(t, item["connectedAt"])

	user, ok := item["user"].(map[string]any)
	require.True(t, ok, "user object must be present")
	assert.Equal(t, "Bob", user["displayName"])
	assert.Equal(t, "bobby", user["handle"])

	// PII-safe: a connection card MUST NOT carry email / national_id / kyc_tier / status.
	for _, leak := range []string{"email", "nationalId", "kycTier", "status", "legalName", "passwordHash"} {
		_, present := user[leak]
		assert.Falsef(t, present, "connection user card must not leak %q", leak)
	}
}

func TestConnectionHandler_List_EmptyArrayNotNull(t *testing.T) {
	users := newFakeUserStore()
	me := seedConnHandlerUser(t, users, "me-empty@example.com")
	conns := &fakeConnStore{} // no accepted rows
	r, signer := buildConnectionRouter(t, users, conns)

	w := doJSON(t, r, http.MethodGet, "/v1/me/connections", tokenFor(t, signer, me), nil)
	require.Equal(t, http.StatusOK, w.Code)
	// Must serialize as [] not null (frontend contract: empty → {connections:[]}).
	assert.Contains(t, w.Body.String(), `"connections":[]`)
}

func TestConnectionHandler_List_Unauthenticated(t *testing.T) {
	users := newFakeUserStore()
	conns := &fakeConnStore{}
	r, _ := buildConnectionRouter(t, users, conns)

	w := doJSON(t, r, http.MethodGet, "/v1/me/connections", "", nil)
	assert.Equal(t, http.StatusUnauthorized, w.Code, "body: %s", w.Body.String())
}

func TestConnectionHandler_ListPending_Splits(t *testing.T) {
	users := newFakeUserStore()
	me := seedConnHandlerUser(t, users, "me-pending@example.com")
	conns := &fakeConnStore{
		incoming: []store.ConnectionWithUser{{ID: uuid.New(), OtherUserID: uuid.New(), DisplayName: "Inviter", Timestamp: time.Now().UTC()}},
		outgoing: []store.ConnectionWithUser{
			{ID: uuid.New(), OtherUserID: uuid.New(), DisplayName: "Target1", Timestamp: time.Now().UTC()},
			{ID: uuid.New(), OtherUserID: uuid.New(), DisplayName: "Target2", Timestamp: time.Now().UTC()},
		},
	}
	r, signer := buildConnectionRouter(t, users, conns)

	w := doJSON(t, r, http.MethodGet, "/v1/me/connections/pending", tokenFor(t, signer, me), nil)
	require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())

	var env struct {
		Data struct {
			Incoming []map[string]any `json:"incoming"`
			Outgoing []map[string]any `json:"outgoing"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &env))
	require.Len(t, env.Data.Incoming, 1)
	require.Len(t, env.Data.Outgoing, 2)
	assert.NotEmpty(t, env.Data.Incoming[0]["createdAt"])
}

func TestConnectionHandler_Send_Created(t *testing.T) {
	users := newFakeUserStore()
	me := seedConnHandlerUser(t, users, "sender@example.com")
	addressee := seedConnHandlerUser(t, users, "target@example.com")
	conns := &fakeConnStore{}
	r, signer := buildConnectionRouter(t, users, conns)

	w := doJSON(t, r, http.MethodPost, "/v1/me/connections", tokenFor(t, signer, me),
		map[string]string{"addresseeUserId": addressee.ID.String()})
	require.Equal(t, http.StatusCreated, w.Code, "body: %s", w.Body.String())

	data := rawDataMap(t, w)
	assert.Equal(t, "pending", data["status"])
	assert.Equal(t, addressee.ID.String(), data["addresseeUserId"])
	assert.NotEmpty(t, data["id"])

	// Identity-from-claims: the persisted requester MUST be the JWT subject, not a body value.
	require.NotNil(t, conns.created)
	assert.Equal(t, me.ID, conns.created.RequesterID, "requester must come from the token, not the body")
	assert.Equal(t, addressee.ID, conns.created.AddresseeID)
}

func TestConnectionHandler_Send_SelfInvite(t *testing.T) {
	users := newFakeUserStore()
	me := seedConnHandlerUser(t, users, "self@example.com")
	conns := &fakeConnStore{}
	r, signer := buildConnectionRouter(t, users, conns)

	w := doJSON(t, r, http.MethodPost, "/v1/me/connections", tokenFor(t, signer, me),
		map[string]string{"addresseeUserId": me.ID.String()})
	require.Equal(t, http.StatusBadRequest, w.Code, "body: %s", w.Body.String())
	assert.Equal(t, "VALIDATION_ERROR", errCode(t, w))
	assert.Nil(t, conns.created, "self-invite must not create an edge")
}

func TestConnectionHandler_Send_NonexistentAddressee(t *testing.T) {
	users := newFakeUserStore()
	me := seedConnHandlerUser(t, users, "sender2@example.com")
	conns := &fakeConnStore{}
	r, signer := buildConnectionRouter(t, users, conns)

	w := doJSON(t, r, http.MethodPost, "/v1/me/connections", tokenFor(t, signer, me),
		map[string]string{"addresseeUserId": uuid.New().String()})
	require.Equal(t, http.StatusNotFound, w.Code, "body: %s", w.Body.String())
	assert.Equal(t, "USER_NOT_FOUND", errCode(t, w))
}

func TestConnectionHandler_Send_MalformedAddressee(t *testing.T) {
	users := newFakeUserStore()
	me := seedConnHandlerUser(t, users, "sender3@example.com")
	conns := &fakeConnStore{}
	r, signer := buildConnectionRouter(t, users, conns)

	w := doJSON(t, r, http.MethodPost, "/v1/me/connections", tokenFor(t, signer, me),
		map[string]string{"addresseeUserId": "not-a-uuid"})
	require.Equal(t, http.StatusBadRequest, w.Code, "body: %s", w.Body.String())
	assert.Equal(t, "VALIDATION_ERROR", errCode(t, w))
}

func TestConnectionHandler_Send_DuplicateConflict(t *testing.T) {
	users := newFakeUserStore()
	me := seedConnHandlerUser(t, users, "sender4@example.com")
	addressee := seedConnHandlerUser(t, users, "target4@example.com")
	conns := &fakeConnStore{createErr: domain.ErrConnectionExists}
	r, signer := buildConnectionRouter(t, users, conns)

	w := doJSON(t, r, http.MethodPost, "/v1/me/connections", tokenFor(t, signer, me),
		map[string]string{"addresseeUserId": addressee.ID.String()})
	require.Equal(t, http.StatusConflict, w.Code, "body: %s", w.Body.String())
	assert.Equal(t, "CONNECTION_EXISTS", errCode(t, w))
}

func TestConnectionHandler_Accept_Success(t *testing.T) {
	users := newFakeUserStore()
	me := seedConnHandlerUser(t, users, "accepter@example.com")
	conns := &fakeConnStore{}
	r, signer := buildConnectionRouter(t, users, conns)

	id := uuid.New()
	w := doJSON(t, r, http.MethodPost, "/v1/me/connections/"+id.String()+"/accept", tokenFor(t, signer, me), nil)
	require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())

	data := rawDataMap(t, w)
	assert.Equal(t, "accepted", data["status"])
	assert.Equal(t, id.String(), data["id"])

	// IDOR-safe: the addressee guard passed to the store MUST be the JWT subject.
	assert.Equal(t, me.ID, conns.lastCaller, "accept must guard on the caller's id")
	assert.Equal(t, id, conns.lastID)
}

func TestConnectionHandler_Accept_NotFound_IDORSafe(t *testing.T) {
	users := newFakeUserStore()
	me := seedConnHandlerUser(t, users, "accepter2@example.com")
	// Wrong-addressee / unknown id both surface ErrConnectionNotFound from the store.
	conns := &fakeConnStore{acceptErr: domain.ErrConnectionNotFound}
	r, signer := buildConnectionRouter(t, users, conns)

	w := doJSON(t, r, http.MethodPost, "/v1/me/connections/"+uuid.New().String()+"/accept", tokenFor(t, signer, me), nil)
	require.Equal(t, http.StatusNotFound, w.Code, "body: %s", w.Body.String())
	assert.Equal(t, "CONNECTION_NOT_FOUND", errCode(t, w), "wrong addressee must be 404, never 403")
}

func TestConnectionHandler_Accept_AlreadyResolvedConflict(t *testing.T) {
	users := newFakeUserStore()
	me := seedConnHandlerUser(t, users, "accepter3@example.com")
	conns := &fakeConnStore{acceptErr: domain.ErrConnectionNotPending}
	r, signer := buildConnectionRouter(t, users, conns)

	w := doJSON(t, r, http.MethodPost, "/v1/me/connections/"+uuid.New().String()+"/accept", tokenFor(t, signer, me), nil)
	require.Equal(t, http.StatusConflict, w.Code, "body: %s", w.Body.String())
	assert.Equal(t, "CONNECTION_NOT_PENDING", errCode(t, w))
}

func TestConnectionHandler_Accept_BadUUID(t *testing.T) {
	users := newFakeUserStore()
	me := seedConnHandlerUser(t, users, "accepter4@example.com")
	conns := &fakeConnStore{}
	r, signer := buildConnectionRouter(t, users, conns)

	w := doJSON(t, r, http.MethodPost, "/v1/me/connections/not-a-uuid/accept", tokenFor(t, signer, me), nil)
	require.Equal(t, http.StatusBadRequest, w.Code, "body: %s", w.Body.String())
	assert.Equal(t, "VALIDATION_ERROR", errCode(t, w))
}

func TestConnectionHandler_Decline_Success(t *testing.T) {
	users := newFakeUserStore()
	me := seedConnHandlerUser(t, users, "decliner@example.com")
	conns := &fakeConnStore{}
	r, signer := buildConnectionRouter(t, users, conns)

	id := uuid.New()
	w := doJSON(t, r, http.MethodPatch, "/v1/me/connections/"+id.String()+"/decline", tokenFor(t, signer, me), nil)
	require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())

	data := rawDataMap(t, w)
	assert.Equal(t, "declined", data["status"])
	assert.Equal(t, me.ID, conns.lastCaller, "decline must guard on the caller's id")
}

func TestConnectionHandler_Decline_NotFound_IDORSafe(t *testing.T) {
	users := newFakeUserStore()
	me := seedConnHandlerUser(t, users, "decliner2@example.com")
	conns := &fakeConnStore{declineErr: domain.ErrConnectionNotFound}
	r, signer := buildConnectionRouter(t, users, conns)

	w := doJSON(t, r, http.MethodPatch, "/v1/me/connections/"+uuid.New().String()+"/decline", tokenFor(t, signer, me), nil)
	require.Equal(t, http.StatusNotFound, w.Code, "body: %s", w.Body.String())
	assert.Equal(t, "CONNECTION_NOT_FOUND", errCode(t, w))
}
