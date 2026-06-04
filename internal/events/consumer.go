// Package events provides the Redis event consumer for the user service.
// This service CONSUMES events (pub/sub) to keep local state (e.g. kyc_tier) fresh.
package events

import (
	"context"
	"encoding/json"
	"log/slog"
	"strconv"
	"strings"

	"github.com/CoverOnes/user/internal/store"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

// subscribedChannels is the set of Redis pub/sub channels this service consumes.
// CONVENTIONS §14: dotted lowercase <domain>.<event>.
var subscribedChannels = []string{
	"kyc.tier_changed",
}

// maxPayloadBytes is the maximum accepted event payload size (64 KiB).
// Payloads above this limit are logged and silently dropped to prevent DoS.
const maxPayloadBytes = 64 * 1024

// eventEnvelope is the canonical Redis pub/sub payload (CONVENTIONS §14) plus the
// top-level "signature" field required by the EVENT HMAC CONTRACT.
//
// OccurredAt and Version are captured as json.RawMessage (the verbatim wire bytes)
// rather than parsed Go types, so the consumer can recompute the HMAC signature
// over the EXACT textual form the publisher signed — re-serializing a time.Time or
// int could differ byte-for-byte from the publisher's encoding and break the MAC.
type eventEnvelope struct {
	EventID    uuid.UUID       `json:"eventId"`
	OccurredAt json.RawMessage `json:"occurredAt"`
	Version    json.RawMessage `json:"version"`
	Data       json.RawMessage `json:"data"`
	Signature  string          `json:"signature"`
}

// kycTierChangedData is the data payload for kyc.tier_changed events.
type kycTierChangedData struct {
	UserID  uuid.UUID `json:"userId"`
	OldTier int16     `json:"oldTier"`
	NewTier int16     `json:"newTier"`
}

// Consumer subscribes to Redis event channels and applies local state updates.
type Consumer struct {
	rdb    *redis.Client
	users  store.UserStore
	secret []byte // EVENT_HMAC_SECRET; events whose signature does not verify are dropped
}

// NewConsumer creates a Consumer. If rdb is nil the consumer is a no-op (dev mode).
//
// secret is the shared EVENT_HMAC_SECRET used to authenticate inbound events. Every
// kyc.tier_changed event MUST carry a valid HMAC signature (see signature.go); an
// event with a missing or mismatched signature is logged and dropped WITHOUT
// applying the tier change, so a forged Redis publish cannot elevate a user's tier.
// An empty secret (dev-only; config.validate rejects it outside development) causes
// all signed events to fail verification and be dropped — fail-closed by design.
func NewConsumer(rdb *redis.Client, users store.UserStore, secret string) *Consumer {
	return &Consumer{rdb: rdb, users: users, secret: []byte(secret)}
}

// Run starts the subscription loop. Blocks until ctx is canceled.
// Designed to run in a goroutine with a context.Background()-derived context so
// that it is not canceled when a request context expires.
// Resilient: bad/unknown payload -> slog.Warn + skip, NEVER crashes the loop.
func (c *Consumer) Run(ctx context.Context) {
	if c.rdb == nil {
		slog.Info("redis consumer disabled: no Redis client configured")
		<-ctx.Done()

		return
	}

	sub := c.rdb.Subscribe(ctx, subscribedChannels...)
	defer func() {
		if err := sub.Close(); err != nil {
			slog.Warn("consumer: close subscription error", "err", err)
		}
	}()

	slog.Info("redis consumer started", "channels", subscribedChannels)

	ch := sub.Channel()

	for {
		select {
		case <-ctx.Done():
			slog.Info("redis consumer stopping")
			return

		case msg, ok := <-ch:
			if !ok {
				slog.Warn("redis consumer channel closed; stopping")
				return
			}

			c.handle(ctx, msg)
		}
	}
}

// handle processes a single pub/sub message.
// All errors are logged as Warn and skipped to keep the loop alive.
func (c *Consumer) handle(ctx context.Context, msg *redis.Message) {
	if len(msg.Payload) > maxPayloadBytes {
		slog.Warn(
			"consumer: oversized event payload; skipping",
			"channel", msg.Channel,
			"size", len(msg.Payload),
		)

		return
	}

	switch msg.Channel {
	case "kyc.tier_changed":
		c.handleKYCTierChanged(ctx, msg.Payload)
	default:
		slog.Warn("consumer: unknown channel; skipping", "channel", msg.Channel)
	}
}

// handleKYCTierChanged processes kyc.tier_changed events and updates users.kyc_tier.
func (c *Consumer) handleKYCTierChanged(ctx context.Context, payload string) {
	var env eventEnvelope
	if err := json.Unmarshal([]byte(payload), &env); err != nil {
		slog.Warn(
			"consumer: malformed event envelope; skipping",
			"channel", "kyc.tier_changed",
			"err", err,
		)

		return
	}

	var data kycTierChangedData
	if err := json.Unmarshal(env.Data, &data); err != nil {
		slog.Warn(
			"consumer: malformed kyc.tier_changed data; skipping",
			"channel", "kyc.tier_changed",
			"event_id", env.EventID,
			"err", err,
		)

		return
	}

	// MESSAGE AUTHENTICATION (P0): recompute the HMAC over the received fields and
	// reject any event whose signature is missing or does not verify in constant
	// time. Without this a forged Redis publish could elevate any user to Tier2.
	sigInput := signatureInput{
		eventID:    env.EventID.String(),
		occurredAt: unquoteJSONString(string(env.OccurredAt)),
		version:    strings.TrimSpace(string(env.Version)),
		userID:     data.UserID.String(),
		newTier:    strconv.FormatInt(int64(data.NewTier), 10),
	}
	if !verifySignature(c.secret, &sigInput, env.Signature) {
		slog.Warn(
			"consumer: kyc.tier_changed signature verification failed; dropping event",
			"channel", "kyc.tier_changed",
			"event_id", env.EventID,
			"user_id", data.UserID,
			"has_signature", env.Signature != "",
		)

		return
	}

	// M2 bounds-check: newTier must be 0–3 (Tier0=unverified … Tier3=highest).
	// Drop and log events outside this range to prevent an out-of-range value
	// from corrupting the DB column (e.g. a negative tier bypassing UI checks).
	const (
		minKYCTier int16 = 0
		maxKYCTier int16 = 3
	)

	if data.NewTier < minKYCTier || data.NewTier > maxKYCTier {
		slog.Warn(
			"consumer: kyc.tier_changed newTier out of bounds; dropping event",
			"channel", "kyc.tier_changed",
			"event_id", env.EventID,
			"user_id", data.UserID,
			"new_tier", data.NewTier,
		)

		return
	}

	if err := c.users.UpdateKYCTier(ctx, data.UserID, data.NewTier); err != nil {
		slog.Warn(
			"consumer: failed to update kyc_tier; skipping",
			"channel", "kyc.tier_changed",
			"event_id", env.EventID,
			"user_id", data.UserID,
			"new_tier", data.NewTier,
			"err", err,
		)

		return
	}

	slog.Info(
		"consumer: kyc_tier updated",
		"channel", "kyc.tier_changed",
		"event_id", env.EventID,
		"user_id", data.UserID,
		"old_tier", data.OldTier,
		"new_tier", data.NewTier,
	)
}
