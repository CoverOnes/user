// Package postgres provides pgxpool-based store implementations.
package postgres

import (
	"context"
	"fmt"
	"regexp"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// poolSchemaNameRe is the same rule as config.schemaNameRe, duplicated here so
// NewPool is safe-by-construction even if called from outside the normal
// config.Load() path. First char must be letter or underscore (leading digits
// are invalid PG identifiers and would cause a startup DoS).
var poolSchemaNameRe = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)

// NewPool creates and validates a pgxpool.Pool with sensible production defaults.
// Connection budget per backend-security-design §5.3.
//
// If schema is non-empty, the pool will:
//  1. Validate the schema name against [a-zA-Z_][a-zA-Z0-9_]* and return an
//     error immediately if invalid (defense-in-depth; config.validate() also
//     enforces this, but NewPool must be safe-by-construction).
//  2. Create the schema (CREATE SCHEMA IF NOT EXISTS) once on startup.
//  3. Set search_path=<schema>, public for every connection via AfterConnect so
//     all queries resolve against the schema first; public is kept as a fallback
//     so extension functions (e.g. pgcrypto) remain resolvable.
//
// If schema is empty the pool behaves identically to before (public schema).
func NewPool(ctx context.Context, dsn, schema string) (*pgxpool.Pool, error) {
	if schema != "" && !poolSchemaNameRe.MatchString(schema) {
		return nil, fmt.Errorf("invalid schema name %q: must match ^[a-zA-Z_][a-zA-Z0-9_]*$", schema)
	}

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
		// schema validated above; ", public" fallback keeps extension functions
		// (e.g. pgcrypto) resolvable without polluting the schema namespace.
		cfg.AfterConnect = func(connectCtx context.Context, conn *pgx.Conn) error {
			_, execErr := conn.Exec(connectCtx, "SET search_path = "+schema+", public")
			if execErr != nil {
				return fmt.Errorf("set search_path=%s,public: %w", schema, execErr)
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
		// Safe: schema name validated above as [a-zA-Z_][a-zA-Z0-9_]*.
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
