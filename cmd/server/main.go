// Command server starts the CoverOnes user microservice.
package main

import (
	"context"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	neturl "net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/CoverOnes/user/internal/auth/jwt"
	"github.com/CoverOnes/user/internal/config"
	"github.com/CoverOnes/user/internal/crypto/pii"
	"github.com/CoverOnes/user/internal/events"
	"github.com/CoverOnes/user/internal/handler"
	"github.com/CoverOnes/user/internal/mailer"
	"github.com/CoverOnes/user/internal/platform/logger"
	"github.com/CoverOnes/user/internal/platform/middleware"
	"github.com/CoverOnes/user/internal/service"
	"github.com/CoverOnes/user/internal/store/postgres"
	"github.com/redis/go-redis/v9"
)

func main() {
	healthcheck := flag.Bool("healthcheck", false, "perform a liveness check against /healthz and exit 0/1")
	flag.Parse()

	// Docker HEALTHCHECK mode: GET /healthz and exit immediately (F12).
	if *healthcheck {
		if err := runHealthCheck(); err != nil {
			slog.Error("healthcheck failed", "err", err)
			os.Exit(1)
		}
		os.Exit(0)
	}

	if err := run(); err != nil {
		slog.Error("server exited with error", "err", err)
		os.Exit(1)
	}
}

// newPIIEncryptor decodes the base64 PII key and builds an AES-256-GCM encryptor.
// config.validate() already fail-fasts on a missing / wrong-length key outside
// dev; this re-decodes to construct the cipher and surfaces any residual error.
func newPIIEncryptor(keyB64 string) (*pii.Encryptor, error) {
	key, err := base64.StdEncoding.DecodeString(keyB64)
	if err != nil {
		// Do not echo the key material in the error.
		return nil, fmt.Errorf("decode USER_PII_ENCRYPTION_KEY base64: %w", err)
	}

	enc, err := pii.NewEncryptor(key)
	if err != nil {
		return nil, fmt.Errorf("build pii encryptor: %w", err)
	}

	return enc, nil
}

// runHealthCheck issues a GET to the local /healthz endpoint.
// It reads PORT from the USER_PORT environment variable (default 8080).
func runHealthCheck() error {
	port := os.Getenv("USER_PORT")
	if port == "" {
		port = "8080"
	}

	url := fmt.Sprintf("http://127.0.0.1:%s/healthz", port)

	client := &http.Client{Timeout: 2 * time.Second}

	resp, err := client.Get(url) //nolint:noctx // healthcheck is a one-shot process; no request context needed
	if err != nil {
		return fmt.Errorf("GET %s: %w", url, err)
	}

	defer resp.Body.Close() //nolint:errcheck // best-effort close on healthcheck response

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status %d from %s", resp.StatusCode, url)
	}

	return nil
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	// Logger — JSON to stdout.
	log := logger.New(cfg.LogLevel)
	slog.SetDefault(log)

	ctx := context.Background()

	// Postgres pool.
	// cfg.PostgresSchema is "" by default (public schema); set USER_DB_SCHEMA
	// to isolate this service within a shared Aiven database.
	// cfg.DBMaxConns / cfg.DBMinConns default to 10 / 2 and can be tuned via
	// USER_DB_MAX_CONNS / USER_DB_MIN_CONNS for shared Aiven plans.
	// int→int32 narrowing is safe: config.validate() enforces 0-1000 bounds.
	// G115 (integer overflow int→uint32) is excluded project-wide in .golangci.yml.
	maxConns := int32(cfg.DBMaxConns)
	minConns := int32(cfg.DBMinConns)
	pool, err := postgres.NewPool(ctx, cfg.PostgresDSN, cfg.PostgresSchema, maxConns, minConns)
	if err != nil {
		return fmt.Errorf("connect postgres: %w", err)
	}

	defer pool.Close()

	slog.Info("postgres connected")

	// JWT signer — ephemeral key in dev if none provided.
	var signer *jwt.Signer

	accessTTL := time.Duration(cfg.AccessTokenTTLSec) * time.Second

	if cfg.JWTPrivateKey != "" {
		signer, err = jwt.NewSignerFromSeed(cfg.JWTPrivateKey, accessTTL)
		if err != nil {
			return fmt.Errorf("create jwt signer: %w", err)
		}
	} else {
		signer, err = jwt.NewEphemeralSigner(accessTTL)
		if err != nil {
			return fmt.Errorf("create ephemeral jwt signer: %w", err)
		}
	}

	// Redis client (optional — nil means rate limiting passes through in dev).
	var redisClient *redis.Client
	if cfg.RedisURL != "" {
		opts, parseErr := redis.ParseURL(cfg.RedisURL)
		if parseErr != nil {
			return fmt.Errorf("parse redis url: %w", parseErr)
		}

		redisClient = redis.NewClient(opts)

		pingCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()

		if pingErr := redisClient.Ping(pingCtx).Err(); pingErr != nil {
			slog.Warn("redis ping failed; rate limiting will be disabled", "err", pingErr)
			redisClient = nil
		} else {
			slog.Info("redis connected")
		}
	}

	// Store layer.
	userStore := postgres.NewUserStore(pool)
	companyStore := postgres.NewCompanyStore(pool)
	rtStore := postgres.NewRefreshTokenStore(pool)
	verificationStore := postgres.NewVerificationStore(pool)
	txMgr := postgres.NewTxManager(pool)

	// PII encryptor — config.validate() guarantees a usable key (32 bytes outside
	// dev; a documented dev-default in dev). Decode + construct here so register
	// always has the encrypt path.
	encryptor, err := newPIIEncryptor(cfg.PIIEncryptionKey)
	if err != nil {
		return fmt.Errorf("init pii encryptor: %w", err)
	}

	// Verification mailer — selected by USER_MAILER_BACKEND (smtp|comms; default smtp).
	verificationMailer, err := buildMailer(cfg)
	if err != nil {
		return fmt.Errorf("init mailer: %w", err)
	}

	// Service layer.
	// Per-email login rate limit (credential-stuffing defense, P1): 5 attempts per
	// 15 minutes per normalized email, in addition to the per-IP middleware limiter.
	// Fails safe (allows) when Redis is unavailable.
	emailLoginLimiter := middleware.NewEmailLoginLimiter(redisClient, 5, 15*time.Minute)

	// Per-email resend-verification limit: 3 per hour (no enumeration; throttled
	// callers are silently dropped). Fails safe (allows) when Redis is unavailable.
	resendLimiter := middleware.NewEmailVerificationLimiter(redisClient, 3, time.Hour)

	authSvc := service.NewAuthService(
		userStore, companyStore, rtStore,
		txMgr,
		signer,
		accessTTL,
		cfg.RefreshTokenTTLHours,
	).WithLoginRateLimiter(emailLoginLimiter).
		WithVerification(verificationStore, encryptor, verificationMailer, resendLimiter)
	profileSvc := service.NewProfileService(userStore)

	// MFA (TOTP 2FA) service — Increment 3 primitives. Reuses the SAME PII encryptor
	// so the TOTP secret + backup codes are AES-256-GCM at rest. cfg.MFAEnforced is
	// intentionally NOT read here: login is unchanged this wave (enforcement is a
	// later, flag-gated increment) and the MFA service only manages enroll/confirm/
	// verify/disable state.
	mfaSvc := service.NewMFAService(userStore, encryptor, cfg.TOTPIssuer)

	// Redis event consumer — subscribes to kyc.tier_changed to keep users.kyc_tier fresh.
	// Runs in a goroutine with a context derived from context.Background() so it is not
	// canceled when HTTP request contexts expire (backend-security-design §5).
	// cfg.EventHMACSecret authenticates inbound events: a kyc.tier_changed event
	// whose HMAC signature is missing or invalid is dropped (a forged Redis publish
	// cannot elevate a user's KYC tier). config.validate() requires the secret
	// outside development.
	consumer := events.NewConsumer(redisClient, userStore, cfg.EventHMACSecret)

	go consumer.Run(ctx)

	// Router.
	r := handler.NewRouter(handler.RouterConfig{
		Auth:    authSvc,
		Profile: profileSvc,
		MFA:     mfaSvc,
		Signer:  signer,
		Pool:    pool,
		Redis:   redisClient,
	})

	srv := &http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.Port),
		Handler:      r,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Graceful shutdown.
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		slog.Info("server starting", "addr", srv.Addr)

		if listenErr := srv.ListenAndServe(); listenErr != nil && !errors.Is(listenErr, http.ErrServerClosed) {
			slog.Error("server listen error", "err", listenErr)
			os.Exit(1)
		}
	}()

	<-quit
	slog.Info("shutting down gracefully")

	shutdownCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	if shutdownErr := srv.Shutdown(shutdownCtx); shutdownErr != nil {
		return fmt.Errorf("server shutdown: %w", shutdownErr)
	}

	// Drain any in-flight detached verification-email sends before exiting so a
	// shutdown does not silently drop a send dispatched just before SIGTERM.
	authSvc.WaitForPendingSends()

	slog.Info("server stopped")

	return nil
}

// buildMailer selects and constructs the verification mailer from config.
// Extracted to keep run()'s cyclomatic complexity within the lint threshold.
//
//   - "comms"          → CommsMailer posting to the notification service.
//   - "smtp" (default) → SMTPMailer dialing USER_SMTP_*.
//   - dev + no SMTP    → devLogMailer (logs the verify URL instead of sending).
func buildMailer(cfg *config.Config) (service.Mailer, error) {
	backend := strings.ToLower(strings.TrimSpace(cfg.MailerBackend))

	if backend == "comms" {
		cm, err := mailer.NewCommsMailer(&mailer.CommsConfig{
			BaseURL:    cfg.CommsBaseURL,
			ServiceID:  "user-service",
			S2SToken:   cfg.CommsS2SToken,
			AppBaseURL: cfg.AppBaseURL,
		})
		if err != nil {
			return nil, fmt.Errorf("init comms mailer: %w", err)
		}

		slog.Info("verification mailer: comms (notification service)", "base_url", cfg.CommsBaseURL)

		return cm, nil
	}

	// smtp or empty (default).
	if cfg.SMTPHost != "" {
		m, err := mailer.NewSMTPMailer(&mailer.Config{
			Host:       cfg.SMTPHost,
			Port:       cfg.SMTPPort,
			Username:   cfg.SMTPUsername,
			Password:   cfg.SMTPPassword,
			From:       cfg.SMTPFrom,
			AppBaseURL: cfg.AppBaseURL,
		})
		if err != nil {
			return nil, fmt.Errorf("init smtp mailer: %w", err)
		}

		slog.Info("verification mailer: smtp", "host", cfg.SMTPHost)

		return m, nil
	}

	// Dev-only fallback: log the verification URL instead of sending.
	// config.validate() rejects this path outside development.
	if !cfg.IsDev() {
		return nil, fmt.Errorf("USER_SMTP_HOST required outside development when USER_MAILER_BACKEND is not comms")
	}

	slog.Warn("USER_SMTP_HOST not set; verification email path will be logged (dev only)")

	return devLogMailer{appBaseURL: cfg.AppBaseURL}, nil
}

type devLogMailer struct {
	appBaseURL string
}

func (m devLogMailer) SendVerification(ctx context.Context, to, token string) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	base := strings.TrimRight(strings.TrimSpace(m.appBaseURL), "/")
	attrs := []any{"to", to}

	if base != "" {
		// Log the clickable verify URL (no raw token in the log — M1 security fix).
		attrs = append(attrs, "verify_url", fmt.Sprintf("%s/verify-email?token=%s", base, neturl.QueryEscape(token)))
	} else {
		// Raw token MUST NOT appear in logs even in dev (credential in logs — M1).
		attrs = append(attrs, "verify_token", "[REDACTED]", "hint", "set USER_APP_BASE_URL to log a clickable verification link")
	}

	slog.Warn(
		"DEV EMAIL VERIFICATION LINK",
		attrs...,
	)

	return nil
}
