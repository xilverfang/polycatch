package storage

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	_ "github.com/mattn/go-sqlite3" // SQLite driver
)

// Database wraps the SQLite connection with Polycatch-specific functionality
type Database struct {
	db     *sql.DB
	path   string
	mu     sync.RWMutex
	closed bool
}

// Config contains database configuration options
type Config struct {
	// Path is the path to the SQLite database file
	Path string

	// MaxOpenConns is the maximum number of open connections
	MaxOpenConns int

	// MaxIdleConns is the maximum number of idle connections
	MaxIdleConns int

	// ConnMaxLifetime is the maximum connection lifetime
	ConnMaxLifetime time.Duration
}

// DefaultConfig returns the default database configuration
func DefaultConfig() Config {
	return Config{
		Path:            "./polycatch.db",
		MaxOpenConns:    10,
		MaxIdleConns:    5,
		ConnMaxLifetime: time.Hour,
	}
}

// Open opens a new database connection and runs migrations
func Open(cfg Config) (*Database, error) {
	// Ensure directory exists
	dir := filepath.Dir(cfg.Path)
	if dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return nil, fmt.Errorf("failed to create database directory: %w", err)
		}
	}

	// Open SQLite connection with secure settings
	// _journal_mode=WAL: Write-Ahead Logging for better concurrency
	// _busy_timeout=5000: Wait 5 seconds before returning BUSY
	// _foreign_keys=ON: Enforce foreign key constraints
	// _secure_delete=ON: Overwrite deleted data with zeros
	dsn := fmt.Sprintf("%s?_journal_mode=WAL&_busy_timeout=5000&_foreign_keys=ON&_secure_delete=ON", cfg.Path)

	db, err := sql.Open("sqlite3", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Configure connection pool
	db.SetMaxOpenConns(cfg.MaxOpenConns)
	db.SetMaxIdleConns(cfg.MaxIdleConns)
	db.SetConnMaxLifetime(cfg.ConnMaxLifetime)

	// Verify connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	// Enforce restrictive permissions on the database file.
	// SQLite may create the file with broader permissions depending on umask.
	if err := os.Chmod(cfg.Path, 0600); err != nil && !os.IsNotExist(err) {
		db.Close()
		return nil, fmt.Errorf("failed to set database file permissions: %w", err)
	}

	database := &Database{
		db:     db,
		path:   cfg.Path,
		closed: false,
	}

	// Run migrations
	if err := database.migrate(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to run migrations: %w", err)
	}

	return database, nil
}

// Close closes the database connection
func (d *Database) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.closed {
		return nil
	}

	d.closed = true
	return d.db.Close()
}

// DB returns the underlying sql.DB for advanced operations
func (d *Database) DB() *sql.DB {
	return d.db
}

// migrate runs all database migrations
func (d *Database) migrate(ctx context.Context) error {
	// Create migrations table if not exists
	_, err := d.db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS migrations (
			id INTEGER PRIMARY KEY,
			name TEXT NOT NULL UNIQUE,
			applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)
	`)
	if err != nil {
		return fmt.Errorf("failed to create migrations table: %w", err)
	}

	// Run migrations in order
	migrations := []struct {
		name string
		sql  string
	}{
		{"001_create_users", migrationCreateUsers},
		{"002_create_trades", migrationCreateTrades},
		{"003_create_audit_logs", migrationCreateAuditLogs},
		{"004_create_deposit_signals", migrationCreateDepositSignals},
	}

	for _, m := range migrations {
		// Check if migration was already applied
		var count int
		err := d.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM migrations WHERE name = ?", m.name).Scan(&count)
		if err != nil {
			return fmt.Errorf("failed to check migration %s: %w", m.name, err)
		}

		if count > 0 {
			continue // Already applied
		}

		// Apply migration
		if _, err := d.db.ExecContext(ctx, m.sql); err != nil {
			return fmt.Errorf("failed to apply migration %s: %w", m.name, err)
		}

		// Record migration
		if _, err := d.db.ExecContext(ctx, "INSERT INTO migrations (name) VALUES (?)", m.name); err != nil {
			return fmt.Errorf("failed to record migration %s: %w", m.name, err)
		}
	}

	return nil
}

// Transaction executes a function within a database transaction
func (d *Database) Transaction(ctx context.Context, fn func(*sql.Tx) error) error {
	d.mu.RLock()
	if d.closed {
		d.mu.RUnlock()
		return ErrDatabaseClosed
	}
	d.mu.RUnlock()

	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}

	if err := fn(tx); err != nil {
		if rbErr := tx.Rollback(); rbErr != nil {
			return fmt.Errorf("transaction error: %v, rollback error: %v", err, rbErr)
		}
		return err
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

// Migration SQL statements
const migrationCreateUsers = `
CREATE TABLE IF NOT EXISTS users (
	telegram_id INTEGER PRIMARY KEY,
	username TEXT NOT NULL DEFAULT '',
	salt BLOB NOT NULL,
	encrypted_credentials TEXT NOT NULL,
	settings TEXT NOT NULL DEFAULT '{}',
	is_active INTEGER NOT NULL DEFAULT 1,
	created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
	updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
	last_active_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_users_is_active ON users(is_active);
`

const migrationCreateTrades = `
CREATE TABLE IF NOT EXISTS trades (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	telegram_id INTEGER NOT NULL,
	token_id TEXT NOT NULL,
	market_question TEXT NOT NULL DEFAULT '',
	side TEXT NOT NULL CHECK (side IN ('BUY', 'SELL')),
	outcome TEXT NOT NULL CHECK (outcome IN ('YES', 'NO')),
	price REAL NOT NULL,
	amount_usd REAL NOT NULL,
	shares REAL NOT NULL,
	status TEXT NOT NULL CHECK (status IN ('PENDING', 'EXECUTING', 'SUCCESS', 'FAILED', 'SKIPPED')),
	error_message TEXT,
	insider_address TEXT NOT NULL,
	insider_amount REAL NOT NULL DEFAULT 0,
	order_id TEXT,
	transaction_hash TEXT,
	executed_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
	FOREIGN KEY (telegram_id) REFERENCES users(telegram_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_trades_telegram_id ON trades(telegram_id);
CREATE INDEX IF NOT EXISTS idx_trades_status ON trades(status);
CREATE INDEX IF NOT EXISTS idx_trades_executed_at ON trades(executed_at);
CREATE INDEX IF NOT EXISTS idx_trades_insider_address ON trades(insider_address);
`

const migrationCreateAuditLogs = `
CREATE TABLE IF NOT EXISTS audit_logs (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	telegram_id INTEGER,
	action TEXT NOT NULL,
	success INTEGER NOT NULL,
	details TEXT,
	ip_address TEXT,
	created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_audit_logs_telegram_id ON audit_logs(telegram_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_action ON audit_logs(action);
CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs(created_at);
`

const migrationCreateDepositSignals = `
CREATE TABLE IF NOT EXISTS deposit_signals (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	address TEXT NOT NULL,
	amount REAL NOT NULL,
	transaction_hash TEXT NOT NULL UNIQUE,
	block_number INTEGER NOT NULL,
	detected_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
	trades_detected INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_deposit_signals_address ON deposit_signals(address);
CREATE INDEX IF NOT EXISTS idx_deposit_signals_detected_at ON deposit_signals(detected_at);
`
