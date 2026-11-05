package db

import (
	"path/filepath"
	"testing"
)

func newTestStore(t *testing.T) *Store {
	t.Setenv("LOCKBOX_DB_PATH", filepath.Join(t.TempDir(), "lockbox.db"))
	s, err := NewStore()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// A deleted key's note and tags must never be reported (AllMeta feeds the
// server's /meta endpoint and tag selection), and they come back with the key.
func TestAllMetaExcludesDeletedKeys(t *testing.T) {
	s := newTestStore(t)
	for _, k := range []string{"A", "B"} {
		if err := s.SetSecret(k, []byte("enc-"+k)); err != nil {
			t.Fatal(err)
		}
		if err := s.SetNote(k, "note "+k); err != nil {
			t.Fatal(err)
		}
		if err := s.AddTags(k, []string{"t1"}); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.DeleteSecret("A"); err != nil {
		t.Fatal(err)
	}
	m, err := s.AllMeta()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := m["A"]; ok || m["B"].Note != "note B" {
		t.Fatalf("AllMeta after delete: %+v", m)
	}
	if c, _ := s.TagCounts(); c["t1"] != 1 {
		t.Fatalf("tag counts after delete: %v", c)
	}
	if err := s.SetNote("A", "x"); err != ErrNotFound {
		t.Fatalf("SetNote on deleted key: %v", err)
	}
	if err := s.Rollback("A"); err != nil {
		t.Fatal(err)
	}
	m, _ = s.AllMeta()
	if m["A"].Note != "note A" || len(m["A"].Tags) != 1 {
		t.Fatalf("meta not restored with the key: %+v", m["A"])
	}
}

func TestNormalizeTagAndValidateNote(t *testing.T) {
	for in, want := range map[string]string{"Env:MainNet": "env:mainnet", " a-b_c.d ": "a-b_c.d"} {
		if got, err := NormalizeTag(in); err != nil || got != want {
			t.Errorf("NormalizeTag(%q) = %q, %v", in, got, err)
		}
	}
	for _, bad := range []string{"", "-x", "a b", "a/b", "é"} {
		if _, err := NormalizeTag(bad); err == nil {
			t.Errorf("NormalizeTag(%q) accepted", bad)
		}
	}
	if ValidateNote("a\nb") == nil || ValidateNote("a\rb") == nil {
		t.Error("newline accepted in note")
	}
}
