package main

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// setupTest creates a temporary database directory and sets up the environment for testing
func setupTest(t *testing.T) (dbPath string, cleanup func()) {
	// Create a temporary directory for this test
	testDir := filepath.Join("/tmp", fmt.Sprintf("lockbox-test-%d", time.Now().UnixNano()))
	if err := os.MkdirAll(testDir, 0700); err != nil {
		t.Fatalf("Failed to create test directory: %v", err)
	}

	dbPath = filepath.Join(testDir, "lockbox.db")

	// Set the environment variable for the database path
	originalDbPath := os.Getenv("LOCKBOX_DB_PATH")
	os.Setenv("LOCKBOX_DB_PATH", dbPath)

	// Return cleanup function
	cleanup = func() {
		// Restore original environment
		if originalDbPath == "" {
			os.Unsetenv("LOCKBOX_DB_PATH")
		} else {
			os.Setenv("LOCKBOX_DB_PATH", originalDbPath)
		}
		// Remove test directory
		_ = os.RemoveAll(testDir)
	}

	return dbPath, cleanup
}

// runLockbox executes the lockbox binary and captures output
func runLockbox(args ...string) (stdout string, stderr string, exitCode int) {
	cmd := exec.Command("./lockbox", args...)

	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf

	err := cmd.Run()
	exitCode = 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			// Command not found or other error
			exitCode = 1
		}
	}

	return outBuf.String(), errBuf.String(), exitCode
}

// TestInit tests that `lockbox init` creates database and encryption key
func TestInit(t *testing.T) {
	dbPath, cleanup := setupTest(t)
	defer cleanup()

	stdout, stderr, exitCode := runLockbox("init")

	if exitCode != 0 {
		t.Errorf("Expected exit code 0, got %d. Stderr: %s", exitCode, stderr)
	}

	if !strings.Contains(stdout, "Lockbox initialized successfully") {
		t.Errorf("Expected success message, got: %s", stdout)
	}

	// Verify database file exists
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		t.Errorf("Database file not created at %s", dbPath)
	}
}

// TestInitIdempotent tests that running init twice doesn't overwrite key
func TestInitIdempotent(t *testing.T) {
	_, cleanup := setupTest(t)
	defer cleanup()

	// First init
	_, _, exitCode1 := runLockbox("init")
	if exitCode1 != 0 {
		t.Fatalf("First init failed with exit code %d", exitCode1)
	}

	// Second init should say key already exists
	stdout2, _, exitCode2 := runLockbox("init")
	if exitCode2 != 0 {
		t.Errorf("Second init should succeed with exit code 0, got %d", exitCode2)
	}

	if !strings.Contains(stdout2, "already initialized") {
		t.Errorf("Expected 'already initialized' message, got: %s", stdout2)
	}
}

// TestSetAndGet tests setting a secret and retrieving it
func TestSetAndGet(t *testing.T) {
	_, cleanup := setupTest(t)
	defer cleanup()

	// Initialize
	runLockbox("init")

	// Set a secret
	stdout, stderr, exitCode := runLockbox("set", "MY_SECRET", "super_secret_value")
	if exitCode != 0 {
		t.Errorf("Set failed with exit code %d. Stderr: %s", exitCode, stderr)
	}

	if !strings.Contains(stdout, "Secret 'MY_SECRET' set successfully") {
		t.Errorf("Expected success message, got: %s", stdout)
	}

	// Get the secret back
	stdout, stderr, exitCode = runLockbox("get", "MY_SECRET")
	if exitCode != 0 {
		t.Errorf("Get failed with exit code %d. Stderr: %s", exitCode, stderr)
	}

	if stdout != "super_secret_value" {
		t.Errorf("Expected 'super_secret_value', got: %s", stdout)
	}
}

// TestSetOverwrite tests that setting the same key overwrites the value
func TestSetOverwrite(t *testing.T) {
	_, cleanup := setupTest(t)
	defer cleanup()

	// Initialize
	runLockbox("init")

	// Set initial value
	runLockbox("set", "API_KEY", "old_value")

	// Overwrite with new value
	runLockbox("set", "API_KEY", "new_value")

	// Get should return new value
	stdout, _, exitCode := runLockbox("get", "API_KEY")
	if exitCode != 0 {
		t.Fatalf("Get failed with exit code %d", exitCode)
	}

	if stdout != "new_value" {
		t.Errorf("Expected 'new_value' after overwrite, got: %s", stdout)
	}
}

// TestGetNotFound tests that getting a non-existent key fails
func TestGetNotFound(t *testing.T) {
	_, cleanup := setupTest(t)
	defer cleanup()

	// Initialize
	runLockbox("init")

	// Try to get non-existent key
	_, stderr, exitCode := runLockbox("get", "NONEXISTENT")

	if exitCode == 0 {
		t.Errorf("Expected non-zero exit code for non-existent key, got 0")
	}

	if !strings.Contains(stderr, "not found") {
		t.Errorf("Expected 'not found' error message, got: %s", stderr)
	}
}

// TestDelete tests deleting a secret
func TestDelete(t *testing.T) {
	_, cleanup := setupTest(t)
	defer cleanup()

	// Initialize
	runLockbox("init")

	// Set a secret
	runLockbox("set", "SECRET_TO_DELETE", "value")

	// Delete it
	stdout, stderr, exitCode := runLockbox("delete", "SECRET_TO_DELETE")
	if exitCode != 0 {
		t.Errorf("Delete failed with exit code %d. Stderr: %s", exitCode, stderr)
	}

	if !strings.Contains(stdout, "deleted successfully") {
		t.Errorf("Expected success message, got: %s", stdout)
	}

	// Verify it's gone
	_, _, exitCode = runLockbox("get", "SECRET_TO_DELETE")
	if exitCode == 0 {
		t.Errorf("Expected non-zero exit code after delete, but key still exists")
	}
}

// TestDeleteNotFound tests that deleting non-existent key fails
func TestDeleteNotFound(t *testing.T) {
	_, cleanup := setupTest(t)
	defer cleanup()

	// Initialize
	runLockbox("init")

	// Try to delete non-existent key
	_, stderr, exitCode := runLockbox("delete", "NONEXISTENT")

	if exitCode == 0 {
		t.Errorf("Expected non-zero exit code for non-existent key, got 0")
	}

	if !strings.Contains(stderr, "not found") {
		t.Errorf("Expected 'not found' error message, got: %s", stderr)
	}
}

// TestList tests listing all secrets
func TestList(t *testing.T) {
	_, cleanup := setupTest(t)
	defer cleanup()

	// Initialize
	runLockbox("init")

	// Set multiple secrets
	runLockbox("set", "SECRET1", "value1")
	runLockbox("set", "SECRET2", "value2")
	runLockbox("set", "SECRET3", "value3")

	// List secrets
	stdout, stderr, exitCode := runLockbox("list")
	if exitCode != 0 {
		t.Errorf("List failed with exit code %d. Stderr: %s", exitCode, stderr)
	}

	// Verify all keys are present
	if !strings.Contains(stdout, "SECRET1") {
		t.Errorf("SECRET1 not found in list: %s", stdout)
	}
	if !strings.Contains(stdout, "SECRET2") {
		t.Errorf("SECRET2 not found in list: %s", stdout)
	}
	if !strings.Contains(stdout, "SECRET3") {
		t.Errorf("SECRET3 not found in list: %s", stdout)
	}
}

// TestListEmpty tests list with no secrets
func TestListEmpty(t *testing.T) {
	_, cleanup := setupTest(t)
	defer cleanup()

	// Initialize
	runLockbox("init")

	// List with no secrets
	stdout, _, exitCode := runLockbox("list")
	if exitCode != 0 {
		t.Errorf("List on empty store failed with exit code %d", exitCode)
	}

	if !strings.Contains(stdout, "No secrets found") {
		t.Errorf("Expected 'No secrets found' message, got: %s", stdout)
	}
}

// TestEnvExport tests `lockbox env` outputs correct format
func TestEnvExport(t *testing.T) {
	_, cleanup := setupTest(t)
	defer cleanup()

	// Initialize
	runLockbox("init")

	// Set some secrets
	runLockbox("set", "DB_HOST", "localhost")
	runLockbox("set", "DB_PORT", "5432")

	// Export to env format
	stdout, stderr, exitCode := runLockbox("env")
	if exitCode != 0 {
		t.Errorf("Env export failed with exit code %d. Stderr: %s", exitCode, stderr)
	}

	// Verify export format
	if !strings.Contains(stdout, "export DB_HOST=\"localhost\"") {
		t.Errorf("Expected 'export DB_HOST=\"localhost\"', got: %s", stdout)
	}
	if !strings.Contains(stdout, "export DB_PORT=\"5432\"") {
		t.Errorf("Expected 'export DB_PORT=\"5432\"', got: %s", stdout)
	}
}

// TestEnvEscaping tests that special characters are escaped properly
func TestEnvEscaping(t *testing.T) {
	_, cleanup := setupTest(t)
	defer cleanup()

	// Initialize
	runLockbox("init")

	// Set a secret with special characters
	runLockbox("set", "COMPLEX_SECRET", `value"with"quotes$and`+"`backticks`")

	// Export to env format
	stdout, _, exitCode := runLockbox("env")
	if exitCode != 0 {
		t.Fatalf("Env export failed with exit code %d", exitCode)
	}

	// Verify escaping is present
	if !strings.Contains(stdout, "export COMPLEX_SECRET=") {
		t.Errorf("COMPLEX_SECRET not found in env output: %s", stdout)
	}

	// Check that special chars are escaped
	if !strings.Contains(stdout, `\"`) || !strings.Contains(stdout, `\$`) {
		t.Errorf("Expected escaped special characters, got: %s", stdout)
	}
}

// TestRun tests `lockbox run -- command` passes env vars
func TestRun(t *testing.T) {
	_, cleanup := setupTest(t)
	defer cleanup()

	// Initialize
	runLockbox("init")

	// Set a secret
	runLockbox("set", "TEST_VAR", "test_value")

	// Run a command that echoes the environment variable
	stdout, stderr, exitCode := runLockbox("run", "--", "sh", "-c", "echo $TEST_VAR")
	if exitCode != 0 {
		t.Errorf("Run failed with exit code %d. Stderr: %s", exitCode, stderr)
	}

	if !strings.Contains(stdout, "test_value") {
		t.Errorf("Expected 'test_value' in output, got: %s", stdout)
	}
}

// TestServer tests HTTP server endpoints
func TestServer(t *testing.T) {
	_, cleanup := setupTest(t)
	defer cleanup()

	// Initialize and set some secrets
	runLockbox("init")
	runLockbox("set", "API_KEY", "secret123")
	runLockbox("set", "DB_URL", "postgres://localhost")

	// Start server in background
	cmd := exec.Command("./lockbox", "serve", "-p", "9876")
	if err := cmd.Start(); err != nil {
		t.Fatalf("Failed to start server: %v", err)
	}
	defer cmd.Process.Kill()

	// Give server time to start
	time.Sleep(500 * time.Millisecond)

	// Test health endpoint
	resp, err := http.Get("http://127.0.0.1:9876/health")
	if err != nil {
		t.Fatalf("Failed to call /health: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Health check returned status %d, expected 200", resp.StatusCode)
	}

	// Test secrets list endpoint
	resp, err = http.Get("http://127.0.0.1:9876/secrets")
	if err != nil {
		t.Fatalf("Failed to call /secrets: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)

	if !strings.Contains(bodyStr, "API_KEY") {
		t.Errorf("Expected API_KEY in secrets list, got: %s", bodyStr)
	}
	if !strings.Contains(bodyStr, "DB_URL") {
		t.Errorf("Expected DB_URL in secrets list, got: %s", bodyStr)
	}

	// Test individual secret endpoint
	resp, err = http.Get("http://127.0.0.1:9876/secrets/API_KEY")
	if err != nil {
		t.Fatalf("Failed to call /secrets/API_KEY: %v", err)
	}
	defer resp.Body.Close()

	body, _ = io.ReadAll(resp.Body)
	if string(body) != "secret123" {
		t.Errorf("Expected 'secret123', got: %s", body)
	}

	// Test env endpoint
	resp, err = http.Get("http://127.0.0.1:9876/env")
	if err != nil {
		t.Fatalf("Failed to call /env: %v", err)
	}
	defer resp.Body.Close()

	body, _ = io.ReadAll(resp.Body)
	bodyStr = string(body)

	if !strings.Contains(bodyStr, "export API_KEY") {
		t.Errorf("Expected export format in env, got: %s", bodyStr)
	}
}

// TestRemoteEnv tests `lockbox env --remote` fetches from server
func TestRemoteEnv(t *testing.T) {
	_, cleanup := setupTest(t)
	defer cleanup()

	// Initialize and set secrets
	runLockbox("init")
	runLockbox("set", "REMOTE_SECRET", "remote_value")

	// Start server
	cmd := exec.Command("./lockbox", "serve", "-p", "9877")
	if err := cmd.Start(); err != nil {
		t.Fatalf("Failed to start server: %v", err)
	}
	defer cmd.Process.Kill()

	time.Sleep(500 * time.Millisecond)

	// Fetch env from remote
	stdout, stderr, exitCode := runLockbox("env", "--remote", "127.0.0.1:9877")
	if exitCode != 0 {
		t.Errorf("Remote env fetch failed with exit code %d. Stderr: %s", exitCode, stderr)
	}

	if !strings.Contains(stdout, "REMOTE_SECRET") {
		t.Errorf("Expected REMOTE_SECRET in output, got: %s", stdout)
	}
}

// TestRemoteRun tests `lockbox run --remote` works
func TestRemoteRun(t *testing.T) {
	_, cleanup := setupTest(t)
	defer cleanup()

	// Initialize and set secrets
	runLockbox("init")
	runLockbox("set", "RUN_VAR", "run_value")

	// Start server
	cmd := exec.Command("./lockbox", "serve", "-p", "9878")
	if err := cmd.Start(); err != nil {
		t.Fatalf("Failed to start server: %v", err)
	}
	defer cmd.Process.Kill()

	time.Sleep(500 * time.Millisecond)

	// Run command with remote secrets
	stdout, stderr, exitCode := runLockbox("run", "--remote", "127.0.0.1:9878", "--", "sh", "-c", "echo $RUN_VAR")
	if exitCode != 0 {
		t.Errorf("Remote run failed with exit code %d. Stderr: %s", exitCode, stderr)
	}

	if !strings.Contains(stdout, "run_value") {
		t.Errorf("Expected 'run_value' in output, got: %s", stdout)
	}
}

// TestNoInitError tests that operations without init fail properly
func TestNoInitError(t *testing.T) {
	_, cleanup := setupTest(t)
	defer cleanup()

	// Don't run init - should fail
	_, stderr, exitCode := runLockbox("set", "KEY", "value")

	if exitCode == 0 {
		t.Errorf("Expected non-zero exit code when not initialized, got 0")
	}

	if !strings.Contains(stderr, "initialization key not found") && !strings.Contains(stderr, "init") {
		t.Errorf("Expected initialization error message, got: %s", stderr)
	}
}

// TestMultipleSecrets tests handling many secrets at once
func TestMultipleSecrets(t *testing.T) {
	_, cleanup := setupTest(t)
	defer cleanup()

	// Initialize
	runLockbox("init")

	// Set many secrets
	for i := 0; i < 10; i++ {
		key := fmt.Sprintf("SECRET_%d", i)
		value := fmt.Sprintf("value_%d", i)
		runLockbox("set", key, value)
	}

	// Verify all can be retrieved
	for i := 0; i < 10; i++ {
		key := fmt.Sprintf("SECRET_%d", i)
		expected := fmt.Sprintf("value_%d", i)

		stdout, _, exitCode := runLockbox("get", key)
		if exitCode != 0 {
			t.Errorf("Failed to get %s", key)
		}

		if stdout != expected {
			t.Errorf("Expected %s, got %s", expected, stdout)
		}
	}

	// Verify list shows all
	stdout, _, _ := runLockbox("list")
	for i := 0; i < 10; i++ {
		key := fmt.Sprintf("SECRET_%d", i)
		if !strings.Contains(stdout, key) {
			t.Errorf("Expected %s in list", key)
		}
	}
}

// TestLargeValue tests handling large secret values
func TestLargeValue(t *testing.T) {
	_, cleanup := setupTest(t)
	defer cleanup()

	// Initialize
	runLockbox("init")

	// Create a large value (10KB)
	largeValue := strings.Repeat("A", 10240)

	// Set and retrieve
	runLockbox("set", "LARGE_SECRET", largeValue)

	stdout, _, exitCode := runLockbox("get", "LARGE_SECRET")
	if exitCode != 0 {
		t.Fatalf("Failed to get large secret")
	}

	if stdout != largeValue {
		t.Errorf("Large value not preserved correctly. Length: expected %d, got %d", len(largeValue), len(stdout))
	}
}

// TestSpecialCharactersInKeys tests keys with special characters
func TestSpecialCharactersInKeys(t *testing.T) {
	_, cleanup := setupTest(t)
	defer cleanup()

	// Initialize
	runLockbox("init")

	// Set secrets with various characters
	keys := []string{
		"SIMPLE_KEY",
		"key.with.dots",
		"key-with-dashes",
		"KEY_WITH_NUMBERS_123",
	}

	for _, key := range keys {
		value := fmt.Sprintf("value_for_%s", key)
		runLockbox("set", key, value)

		stdout, _, exitCode := runLockbox("get", key)
		if exitCode != 0 {
			t.Errorf("Failed to get key %s", key)
		}

		if stdout != value {
			t.Errorf("Expected %s, got %s for key %s", value, stdout, key)
		}
	}
}
