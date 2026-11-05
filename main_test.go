package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestMain makes it impossible for a test to touch a real lockbox: the whole
// test process (and every ./lockbox it spawns) gets a throwaway HOME, and any
// inherited LOCKBOX_DB_PATH that points outside the temp area aborts the run.
func TestMain(m *testing.M) {
	if p := os.Getenv("LOCKBOX_DB_PATH"); p != "" && !strings.HasPrefix(filepath.Clean(p), "/tmp/") {
		fmt.Fprintf(os.Stderr, "refusing to run tests: LOCKBOX_DB_PATH=%s is outside /tmp\n", p)
		os.Exit(2)
	}
	os.Unsetenv("LOCKBOX_DB_PATH")
	home, err := os.MkdirTemp("", "lockbox-test-home-")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	os.Setenv("HOME", home)
	code := m.Run()
	os.RemoveAll(home)
	os.Exit(code)
}
