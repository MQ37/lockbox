package db

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	_ "modernc.org/sqlite"
)

// ErrNotFound is returned when a key is not found in the store
var ErrNotFound = errors.New("key not found")

// Store provides access to the SQLite database
type Store struct {
	db *sql.DB
}

// NewStore opens or creates the SQLite database and runs migrations
func NewStore() (*Store, error) {
	// Check for custom database path via environment variable
	var dbPath string
	if customPath := os.Getenv("LOCKBOX_DB_PATH"); customPath != "" {
		dbPath = customPath
		// Ensure the directory exists
		dir := filepath.Dir(dbPath)
		if err := os.MkdirAll(dir, 0700); err != nil {
			return nil, fmt.Errorf("failed to create database directory: %w", err)
		}
	} else {
		// Use default ~/.lockbox/lockbox.db
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("failed to get home directory: %w", err)
		}

		lockboxDir := filepath.Join(homeDir, ".lockbox")
		if err := os.MkdirAll(lockboxDir, 0700); err != nil {
			return nil, fmt.Errorf("failed to create lockbox directory: %w", err)
		}

		dbPath = filepath.Join(lockboxDir, "lockbox.db")
	}

	// Open database connection
	db, err := sql.Open("sqlite", "file:"+dbPath+"?cache=shared&mode=rwc")
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Test the connection
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	store := &Store{db: db}

	// Run migrations
	if err := store.migrate(); err != nil {
		db.Close()
		return nil, fmt.Errorf("migration failed: %w", err)
	}

	return store, nil
}

// migrate creates the necessary tables if they don't exist
func (s *Store) migrate() error {
	schema := `
	CREATE TABLE IF NOT EXISTS config (
		key TEXT PRIMARY KEY,
		value BLOB NOT NULL
	);

	CREATE TABLE IF NOT EXISTS secrets (
		key TEXT PRIMARY KEY,
		value BLOB NOT NULL,
		created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
	);
	`

	_, err := s.db.Exec(schema)
	if err != nil {
		return fmt.Errorf("failed to create tables: %w", err)
	}

	return nil
}

// Close closes the database connection
func (s *Store) Close() error {
	if s.db == nil {
		return nil
	}
	return s.db.Close()
}

// GetConfig retrieves a configuration value by key
func (s *Store) GetConfig(key string) ([]byte, error) {
	var value []byte
	err := s.db.QueryRow("SELECT value FROM config WHERE key = ?", key).Scan(&value)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("failed to get config: %w", err)
	}
	return value, nil
}

// SetConfig stores a configuration value
func (s *Store) SetConfig(key string, value []byte) error {
	_, err := s.db.Exec(
		"INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)",
		key, value,
	)
	if err != nil {
		return fmt.Errorf("failed to set config: %w", err)
	}
	return nil
}

// SetSecret stores an encrypted secret value
func (s *Store) SetSecret(key string, encryptedValue []byte) error {
	_, err := s.db.Exec(
		`INSERT OR REPLACE INTO secrets (key, value, created_at, updated_at)
		 VALUES (?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)`,
		key, encryptedValue,
	)
	if err != nil {
		return fmt.Errorf("failed to set secret: %w", err)
	}
	return nil
}

// GetSecret retrieves an encrypted secret value by key
func (s *Store) GetSecret(key string) ([]byte, error) {
	var value []byte
	err := s.db.QueryRow("SELECT value FROM secrets WHERE key = ?", key).Scan(&value)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("failed to get secret: %w", err)
	}
	return value, nil
}

// DeleteSecret removes a secret by key
func (s *Store) DeleteSecret(key string) error {
	result, err := s.db.Exec("DELETE FROM secrets WHERE key = ?", key)
	if err != nil {
		return fmt.Errorf("failed to delete secret: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return ErrNotFound
	}

	return nil
}

// ListSecrets returns all secret keys
func (s *Store) ListSecrets() ([]string, error) {
	rows, err := s.db.Query("SELECT key FROM secrets ORDER BY key ASC")
	if err != nil {
		return nil, fmt.Errorf("failed to list secrets: %w", err)
	}
	defer rows.Close()

	var keys []string
	for rows.Next() {
		var key string
		if err := rows.Scan(&key); err != nil {
			return nil, fmt.Errorf("failed to scan secret key: %w", err)
		}
		keys = append(keys, key)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating secrets: %w", err)
	}

	return keys, nil
}
