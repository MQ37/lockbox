package db

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

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

	// The database holds the encryption key next to the data: keep it private.
	_ = os.Chmod(dbPath, 0600)

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

	CREATE TABLE IF NOT EXISTS secret_history (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		key TEXT NOT NULL,
		value BLOB NOT NULL,
		replaced_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
	);
	CREATE INDEX IF NOT EXISTS secret_history_key ON secret_history (key, id);

	CREATE TABLE IF NOT EXISTS secret_meta (
		key TEXT PRIMARY KEY,
		note TEXT NOT NULL DEFAULT ''
	);
	CREATE TABLE IF NOT EXISTS secret_tags (
		key TEXT NOT NULL,
		tag TEXT NOT NULL,
		PRIMARY KEY (key, tag)
	);
	CREATE INDEX IF NOT EXISTS secret_tags_tag ON secret_tags (tag);
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

// HistoryLimit is how many previous values are kept per key.
const HistoryLimit = 5

// SetSecret stores an encrypted secret value. A different previous value is
// kept in the history (last HistoryLimit entries) so it can be rolled back.
func (s *Store) SetSecret(key string, encryptedValue []byte) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("failed to set secret: %w", err)
	}
	defer tx.Rollback()
	var createdAt string
	var prev []byte
	err = tx.QueryRow("SELECT value, created_at FROM secrets WHERE key = ?", key).Scan(&prev, &createdAt)
	exists := err == nil
	if err != nil && err != sql.ErrNoRows {
		return fmt.Errorf("failed to set secret: %w", err)
	}
	if exists {
		if _, err := tx.Exec("INSERT INTO secret_history (key, value) VALUES (?, ?)", key, prev); err != nil {
			return fmt.Errorf("failed to keep history: %w", err)
		}
		if _, err := tx.Exec(`DELETE FROM secret_history WHERE key = ? AND id NOT IN
			(SELECT id FROM secret_history WHERE key = ? ORDER BY id DESC LIMIT ?)`, key, key, HistoryLimit); err != nil {
			return fmt.Errorf("failed to trim history: %w", err)
		}
		_, err = tx.Exec("UPDATE secrets SET value = ?, updated_at = CURRENT_TIMESTAMP WHERE key = ?", encryptedValue, key)
	} else {
		_, err = tx.Exec("INSERT INTO secrets (key, value) VALUES (?, ?)", key, encryptedValue)
	}
	if err != nil {
		return fmt.Errorf("failed to set secret: %w", err)
	}
	return tx.Commit()
}

// HasSecret reports whether a key exists.
func (s *Store) HasSecret(key string) (bool, error) {
	var n int
	if err := s.db.QueryRow("SELECT COUNT(*) FROM secrets WHERE key = ?", key).Scan(&n); err != nil {
		return false, fmt.Errorf("failed to look up secret: %w", err)
	}
	return n > 0, nil
}

// SecretMeta is the non-secret information about a stored key.
type SecretMeta struct {
	Key       string   `json:"key"`
	CreatedAt string   `json:"created_at,omitempty"`
	UpdatedAt string   `json:"updated_at,omitempty"`
	Note      string   `json:"note"`
	Tags      []string `json:"tags"`
}

// SecretInfo returns timestamps for a key.
func (s *Store) SecretInfo(key string) (SecretMeta, error) {
	m := SecretMeta{Key: key}
	err := s.db.QueryRow("SELECT created_at, updated_at FROM secrets WHERE key = ?", key).Scan(&m.CreatedAt, &m.UpdatedAt)
	if err == sql.ErrNoRows {
		return m, ErrNotFound
	}
	return m, err
}

// ListSecretMeta returns all keys with their timestamps.
func (s *Store) ListSecretMeta() ([]SecretMeta, error) {
	rows, err := s.db.Query("SELECT key, created_at, updated_at FROM secrets ORDER BY key ASC")
	if err != nil {
		return nil, fmt.Errorf("failed to list secrets: %w", err)
	}
	defer rows.Close()
	var out []SecretMeta
	for rows.Next() {
		var m SecretMeta
		if err := rows.Scan(&m.Key, &m.CreatedAt, &m.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	rows.Close()
	all, err := s.AllMeta()
	if err != nil {
		return nil, err
	}
	for i := range out {
		m := all[out[i].Key]
		out[i].Note, out[i].Tags = m.Note, m.Tags
		if out[i].Tags == nil {
			out[i].Tags = []string{}
		}
	}
	return out, nil
}

// HistoryEntry is one previous value of a key (value stays encrypted).
type HistoryEntry struct {
	ID         int64
	ReplacedAt string
}

// History lists the kept previous values of a key, newest first.
func (s *Store) History(key string) ([]HistoryEntry, error) {
	rows, err := s.db.Query("SELECT id, replaced_at FROM secret_history WHERE key = ? ORDER BY id DESC", key)
	if err != nil {
		return nil, fmt.Errorf("failed to read history: %w", err)
	}
	defer rows.Close()
	var out []HistoryEntry
	for rows.Next() {
		var h HistoryEntry
		if err := rows.Scan(&h.ID, &h.ReplacedAt); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// Rollback restores the newest previous value of a key. The value it replaces
// (if the key still exists) goes into the history, so rollback is undoable.
func (s *Store) Rollback(key string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var id int64
	var prev []byte
	err = tx.QueryRow("SELECT id, value FROM secret_history WHERE key = ? ORDER BY id DESC LIMIT 1", key).Scan(&id, &prev)
	if err == sql.ErrNoRows {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if _, err := tx.Exec("DELETE FROM secret_history WHERE id = ?", id); err != nil {
		return err
	}
	var cur []byte
	err = tx.QueryRow("SELECT value FROM secrets WHERE key = ?", key).Scan(&cur)
	if err == nil {
		if _, err := tx.Exec("INSERT INTO secret_history (key, value) VALUES (?, ?)", key, cur); err != nil {
			return err
		}
		_, err = tx.Exec("UPDATE secrets SET value = ?, updated_at = CURRENT_TIMESTAMP WHERE key = ?", prev, key)
	} else if err == sql.ErrNoRows {
		_, err = tx.Exec("INSERT INTO secrets (key, value) VALUES (?, ?)", key, prev)
	}
	if err != nil {
		return err
	}
	return tx.Commit()
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

// DeleteSecret removes a secret by key. Its value moves into the history so a
// mistaken delete can be undone with Rollback.
func (s *Store) DeleteSecret(key string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("failed to delete secret: %w", err)
	}
	defer tx.Rollback()
	var prev []byte
	err = tx.QueryRow("SELECT value FROM secrets WHERE key = ?", key).Scan(&prev)
	if err == sql.ErrNoRows {
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("failed to delete secret: %w", err)
	}
	if _, err := tx.Exec("INSERT INTO secret_history (key, value) VALUES (?, ?)", key, prev); err != nil {
		return fmt.Errorf("failed to keep history: %w", err)
	}
	if _, err := tx.Exec(`DELETE FROM secret_history WHERE key = ? AND id NOT IN
		(SELECT id FROM secret_history WHERE key = ? ORDER BY id DESC LIMIT ?)`, key, key, HistoryLimit); err != nil {
		return fmt.Errorf("failed to trim history: %w", err)
	}
	if _, err := tx.Exec("DELETE FROM secrets WHERE key = ?", key); err != nil {
		return fmt.Errorf("failed to delete secret: %w", err)
	}
	return tx.Commit()
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

// ListConfig returns config entries whose key starts with prefix.
func (s *Store) ListConfig(prefix string) (map[string][]byte, error) {
	rows, err := s.db.Query("SELECT key, value FROM config WHERE key LIKE ? ESCAPE '\\'", escapeLike(prefix)+"%")
	if err != nil {
		return nil, fmt.Errorf("failed to list config: %w", err)
	}
	defer rows.Close()
	out := map[string][]byte{}
	for rows.Next() {
		var k string
		var v []byte
		if err := rows.Scan(&k, &v); err != nil {
			return nil, err
		}
		out[k] = v
	}
	return out, rows.Err()
}

// DeleteConfig removes a config entry; it reports ErrNotFound if absent.
func (s *Store) DeleteConfig(key string) error {
	res, err := s.db.Exec("DELETE FROM config WHERE key = ?", key)
	if err != nil {
		return fmt.Errorf("failed to delete config: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

func escapeLike(s string) string {
	r := ""
	for _, c := range s {
		if c == '%' || c == '_' || c == '\\' {
			r += "\\"
		}
		r += string(c)
	}
	return r
}

// ---- notes and tags --------------------------------------------------------

// Limits and validation for notes and tags. Both are stored in plaintext.
const (
	MaxNoteLen = 300
	MaxTags    = 16
)

var tagRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_.:-]{0,63}$`)

// NormalizeTag lowercases and validates a tag.
func NormalizeTag(t string) (string, error) {
	t = strings.ToLower(strings.TrimSpace(t))
	if !tagRe.MatchString(t) {
		return "", fmt.Errorf("invalid tag %q (use lowercase letters, digits and _ . : -, up to 64 characters)", t)
	}
	return t, nil
}

// ValidateNote checks a note: one line, bounded length.
func ValidateNote(n string) error {
	if strings.ContainsAny(n, "\r\n") {
		return errors.New("a note must be a single line")
	}
	if len(n) > MaxNoteLen {
		return fmt.Errorf("note too long (%d bytes, max %d)", len(n), MaxNoteLen)
	}
	return nil
}

// Meta is the plaintext note and tags of one key.
type Meta struct {
	Note string   `json:"note"`
	Tags []string `json:"tags"`
}

// SetNote sets (or, with "", clears) the note of an existing key.
func (s *Store) SetNote(key, note string) error {
	if err := ValidateNote(note); err != nil {
		return err
	}
	if ok, err := s.HasSecret(key); err != nil {
		return err
	} else if !ok {
		return ErrNotFound
	}
	_, err := s.db.Exec(`INSERT INTO secret_meta (key, note) VALUES (?, ?)
		ON CONFLICT(key) DO UPDATE SET note = excluded.note`, key, strings.TrimSpace(note))
	if err != nil {
		return fmt.Errorf("failed to set note: %w", err)
	}
	return nil
}

// AddTags adds tags to an existing key (already normalized by the caller).
func (s *Store) AddTags(key string, tags []string) error {
	if ok, err := s.HasSecret(key); err != nil {
		return err
	} else if !ok {
		return ErrNotFound
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, t := range tags {
		if _, err := tx.Exec("INSERT OR IGNORE INTO secret_tags (key, tag) VALUES (?, ?)", key, t); err != nil {
			return fmt.Errorf("failed to add tag: %w", err)
		}
	}
	var n int
	if err := tx.QueryRow("SELECT COUNT(*) FROM secret_tags WHERE key = ?", key).Scan(&n); err != nil {
		return err
	}
	if n > MaxTags {
		return fmt.Errorf("too many tags on '%s' (%d, max %d)", key, n, MaxTags)
	}
	return tx.Commit()
}

// RemoveTags removes tags from a key and reports how many were present.
func (s *Store) RemoveTags(key string, tags []string) (int, error) {
	removed := 0
	for _, t := range tags {
		res, err := s.db.Exec("DELETE FROM secret_tags WHERE key = ? AND tag = ?", key, t)
		if err != nil {
			return removed, fmt.Errorf("failed to remove tag: %w", err)
		}
		if n, _ := res.RowsAffected(); n > 0 {
			removed++
		}
	}
	return removed, nil
}

// AllMeta returns notes and tags (sorted) for every key that has any, limited
// to keys that currently exist as secrets.
func (s *Store) AllMeta() (map[string]Meta, error) {
	out := map[string]Meta{}
	rows, err := s.db.Query(`SELECT m.key, m.note FROM secret_meta m JOIN secrets s ON s.key = m.key`)
	if err != nil {
		return nil, fmt.Errorf("failed to read notes: %w", err)
	}
	for rows.Next() {
		var k, n string
		if err := rows.Scan(&k, &n); err != nil {
			rows.Close()
			return nil, err
		}
		out[k] = Meta{Note: n}
	}
	rows.Close()
	trows, err := s.db.Query(`SELECT t.key, t.tag FROM secret_tags t JOIN secrets s ON s.key = t.key ORDER BY t.key, t.tag`)
	if err != nil {
		return nil, fmt.Errorf("failed to read tags: %w", err)
	}
	defer trows.Close()
	for trows.Next() {
		var k, t string
		if err := trows.Scan(&k, &t); err != nil {
			return nil, err
		}
		m := out[k]
		m.Tags = append(m.Tags, t)
		out[k] = m
	}
	return out, trows.Err()
}

// TagCounts returns how many existing keys carry each tag.
func (s *Store) TagCounts() (map[string]int, error) {
	rows, err := s.db.Query(`SELECT t.tag, COUNT(*) FROM secret_tags t JOIN secrets s ON s.key = t.key GROUP BY t.tag`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var t string
		var n int
		if err := rows.Scan(&t, &n); err != nil {
			return nil, err
		}
		out[t] = n
	}
	return out, rows.Err()
}
