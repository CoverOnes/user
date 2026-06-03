// Command server starts the CoverOnes user microservice.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/CoverOnes/user/internal/auth/jwt"
	"github.com/CoverOnes/user/internal/config"
	"github.com/CoverOnes/user/internal/handler"
	"github.com/CoverOnes/user/internal/platform/logger"
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
	txMgr := postgres.NewTxManager(pool)

	// Service layer.
	authSvc := service.NewAuthService(
		userStore, companyStore, rtStore,
		txMgr,
		signer,
		accessTTL,
		cfg.RefreshTokenTTLHours,
	)
	profileSvc := service.NewProfileService(userStore)

	// Router.
	r := handler.NewRouter(handler.RouterConfig{
		Auth:    authSvc,
		Profile: profileSvc,
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

	slog.Info("server stopped")

	return nil
}
