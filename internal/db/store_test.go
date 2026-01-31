package db

import (
	"errors"
	"fmt"
	"os"
	"testing"
	"time"
)

func TestStoreBasicOperations(t *testing.T) {
	// Setup isolated test environment
	tmpDir := fmt.Sprintf("/tmp/lockbox-db-test-%d", time.Now().UnixNano())
	os.MkdirAll(tmpDir, 0700)
	dbPath := tmpDir + "/lockbox.db"
	os.Setenv("LOCKBOX_DB_PATH", dbPath)
	defer func() {
		os.Unsetenv("LOCKBOX_DB_PATH")
		os.RemoveAll(tmpDir)
	}()

	// Create a new store
	store, err := NewStore()
	if err != nil {
		t.Fatalf("Failed to create store: %v", err)
	}
	defer store.Close()

	// Test SetConfig and GetConfig
	testKey := "test_key"
	testValue := []byte("test_value")

	if err := store.SetConfig(testKey, testValue); err != nil {
		t.Fatalf("Failed to set config: %v", err)
	}

	retrieved, err := store.GetConfig(testKey)
	if err != nil {
		t.Fatalf("Failed to get config: %v", err)
	}

	if string(retrieved) != string(testValue) {
		t.Fatalf("Config value mismatch: got %s, expected %s", retrieved, testValue)
	}

	// Test SetSecret and GetSecret
	secretKey := "secret_1"
	secretValue := []byte{1, 2, 3, 4, 5}

	if err := store.SetSecret(secretKey, secretValue); err != nil {
		t.Fatalf("Failed to set secret: %v", err)
	}

	retrieved, err = store.GetSecret(secretKey)
	if err != nil {
		t.Fatalf("Failed to get secret: %v", err)
	}

	if string(retrieved) != string(secretValue) {
		t.Fatalf("Secret value mismatch")
	}

	// Test ListSecrets
	store.SetSecret("secret_2", []byte{5, 6, 7})
	store.SetSecret("secret_3", []byte{8, 9, 10})

	secrets, err := store.ListSecrets()
	if err != nil {
		t.Fatalf("Failed to list secrets: %v", err)
	}

	if len(secrets) != 3 {
		t.Fatalf("Expected 3 secrets, got %d", len(secrets))
	}

	// Test DeleteSecret
	if err := store.DeleteSecret(secretKey); err != nil {
		t.Fatalf("Failed to delete secret: %v", err)
	}

	secrets, err = store.ListSecrets()
	if err != nil {
		t.Fatalf("Failed to list secrets after delete: %v", err)
	}

	if len(secrets) != 2 {
		t.Fatalf("Expected 2 secrets after delete, got %d", len(secrets))
	}

	// Test ErrNotFound
	if err := store.DeleteSecret("nonexistent"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Expected ErrNotFound for non-existent key, got: %v", err)
	}

	_, err = store.GetSecret("nonexistent")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("Expected ErrNotFound for non-existent secret, got: %v", err)
	}

	_, err = store.GetConfig("nonexistent")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("Expected ErrNotFound for non-existent config, got: %v", err)
	}
}
