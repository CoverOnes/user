// Package postgres provides pgxpool-based store implementations.
package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// NewPool creates and validates a pgxpool.Pool with sensible production defaults.
// Connection budget per backend-security-design §5.3.
//
// If schema is non-empty, the pool will:
//  1. Create the schema (CREATE SCHEMA IF NOT EXISTS) once on startup.
//  2. Set search_path=<schema> for every connection via AfterConnect so all
//     queries resolve against the schema without explicit qualification.
//
// If schema is empty the pool behaves identically to before (public schema).
// The caller is responsible for validating that schema matches [a-zA-Z0-9_]+
// before passing it here (config.validate() enforces this).
func NewPool(ctx context.Context, dsn, schema string) (*pgxpool.Pool, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("parse pgx config: %w", err)
	}

	// Connection budget per backend-security-design §5.3.
	cfg.MaxConns = 10
	cfg.MinConns = 2
	cfg.MaxConnLifetime = 30 * time.Minute
	cfg.MaxConnIdleTime = 5 * time.Minute
	cfg.HealthCheckPeriod = 1 * time.Minute

	if schema != "" {
		// AfterConnect sets the search_path for every new connection.
		// The schema name has already been validated to be [a-zA-Z0-9_]+
		// by config.validate() so interpolation is safe.
		cfg.AfterConnect = func(connectCtx context.Context, conn *pgx.Conn) error {
			_, execErr := conn.Exec(connectCtx, "SET search_path = "+schema)
			if execErr != nil {
				return fmt.Errorf("set search_path=%s: %w", schema, execErr)
			}

			return nil
		}
	}

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("create pgxpool: %w", err)
	}

	if schema != "" {
		// Create the schema once on startup (idempotent).
		// Safe: schema name already validated as [a-zA-Z0-9_]+.
		if _, execErr := pool.Exec(ctx, "CREATE SCHEMA IF NOT EXISTS "+schema); execErr != nil {
			pool.Close()
			return nil, fmt.Errorf("create schema %q: %w", schema, execErr)
		}
	}

	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping postgres: %w", err)
	}

	return pool, nil
}
