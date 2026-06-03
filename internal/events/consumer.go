// Package events provides the Redis event consumer for the user service.
// This service CONSUMES events (pub/sub) to keep local state (e.g. kyc_tier) fresh.
package events

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"

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

// eventEnvelope is the canonical Redis pub/sub payload (CONVENTIONS §14).
type eventEnvelope struct {
	EventID    uuid.UUID       `json:"eventId"`
	OccurredAt time.Time       `json:"occurredAt"`
	Version    int             `json:"version"`
	Data       json.RawMessage `json:"data"`
}

// kycTierChangedData is the data payload for kyc.tier_changed events.
type kycTierChangedData struct {
	UserID  uuid.UUID `json:"userId"`
	OldTier int16     `json:"oldTier"`
	NewTier int16     `json:"newTier"`
}

// Consumer subscribes to Redis event channels and applies local state updates.
type Consumer struct {
	rdb   *redis.Client
	users store.UserStore
}

// NewConsumer creates a Consumer. If rdb is nil the consumer is a no-op (dev mode).
func NewConsumer(rdb *redis.Client, users store.UserStore) *Consumer {
	return &Consumer{rdb: rdb, users: users}
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
