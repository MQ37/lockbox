package main

import (
	"encoding/json"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestNoteSetShowClear(t *testing.T) {
	defer setup(t, "K", "value_one_1234")()
	if _, e, c := lb("", nil, "note", "K", "personal wallet, tests only"); c != 0 {
		t.Fatalf("set note: %s", e)
	}
	if o, _, _ := lb("", nil, "note", "K"); strings.TrimSpace(o) != "personal wallet, tests only" {
		t.Fatalf("show: %q", o)
	}
	if _, _, c := lb("", nil, "note", "K", "--clear"); c != 0 {
		t.Fatal("clear")
	}
	if o, _, _ := lb("", nil, "note", "K"); strings.TrimSpace(o) != "" {
		t.Fatalf("not cleared: %q", o)
	}
	if _, e, c := lb("", nil, "note", "NOPE", "x"); c == 0 || !strings.Contains(e, "not found") {
		t.Fatalf("note on missing key: %d %q", c, e)
	}
	if _, _, c := lb("", nil, "note", "K", "a\nb"); c == 0 {
		t.Fatal("multi-line note accepted")
	}
	if _, _, c := lb("", nil, "note", "K", strings.Repeat("x", 301)); c == 0 {
		t.Fatal("301-byte note accepted")
	}
	if _, _, c := lb("", nil, "note", "K", strings.Repeat("x", 300)); c != 0 {
		t.Fatal("300-byte note refused")
	}
}

func TestNoteRefusesSecretValues(t *testing.T) {
	defer setup(t, "A", "supersecretvalue_A", "B", "short")()
	// the value of another secret
	if _, e, c := lb("", nil, "note", "B", "my key is supersecretvalue_A ok"); c == 0 || !strings.Contains(e, "'A'") {
		t.Fatalf("secret in note accepted: %d %q", c, e)
	}
	// the value of its own secret
	if _, _, c := lb("", nil, "note", "A", "supersecretvalue_A"); c == 0 {
		t.Fatal("own value in note accepted")
	}
	// secret in a tag (valid charset) is refused too
	lb("", nil, "set", "C", "tokvalue-12345")
	if _, _, c := lb("", nil, "tag", "add", "B", "tokvalue-12345"); c == 0 {
		t.Fatal("secret in tag accepted")
	}
	// short values (< 8 bytes) are not treated as secrets
	if _, _, c := lb("", nil, "note", "A", "this is short ok"); c != 0 {
		t.Fatal("note containing a short value refused")
	}
	// set --note with the value being stored: refused and NOTHING stored
	_, e, c := lb("", nil, "set", "NEWK", "brandnewvalue99", "--note", "it is brandnewvalue99")
	if c == 0 || !strings.Contains(e, "value being stored") {
		t.Fatalf("set with value in note: %d %q", c, e)
	}
	if _, _, c := lb("", nil, "get", "NEWK"); c == 0 {
		t.Fatal("secret was stored despite refused note")
	}
}

func TestTagAddRmListCounts(t *testing.T) {
	defer setup(t, "A", "va_12345678", "B", "vb_12345678")()
	if _, e, c := lb("", nil, "tag", "add", "A", "Env:MainNet", "kind:wallet-key"); c != 0 {
		t.Fatalf("add: %s", e) // uppercase is normalized
	}
	lb("", nil, "tag", "add", "B", "env:mainnet")
	lb("", nil, "tag", "add", "A", "env:mainnet") // idempotent
	out, _, _ := lb("", nil, "tag", "list")
	if !strings.Contains(out, "env:mainnet\t2") || !strings.Contains(out, "kind:wallet-key\t1") {
		t.Fatalf("tag list: %q", out)
	}
	if _, _, c := lb("", nil, "tag", "rm", "A", "kind:wallet-key"); c != 0 {
		t.Fatal("rm")
	}
	if _, _, c := lb("", nil, "tag", "rm", "A", "kind:wallet-key"); c == 0 {
		t.Fatal("rm of absent tag should fail")
	}
	for _, bad := range []string{"has space", "-lead", "", "x/y", strings.Repeat("a", 65)} {
		if _, _, c := lb("", nil, "tag", "add", "A", bad); c == 0 {
			t.Errorf("tag %q accepted", bad)
		}
	}
	if _, _, c := lb("", nil, "tag", "add", "NOPE", "x"); c == 0 {
		t.Fatal("tag on missing key")
	}
}

func TestTagLimit(t *testing.T) {
	defer setup(t, "A", "va_12345678")()
	for i := 0; i < 16; i++ {
		if _, e, c := lb("", nil, "tag", "add", "A", "t"+string(rune('a'+i))); c != 0 {
			t.Fatalf("tag %d: %s", i, e)
		}
	}
	if _, _, c := lb("", nil, "tag", "add", "A", "onetoomany"); c == 0 {
		t.Fatal("17th tag accepted")
	}
	// the refused add must not have been stored
	if o, _, _ := lb("", nil, "list", "--tag", "onetoomany"); o != "" {
		t.Fatalf("refused tag stored: %q", o)
	}
}

func TestSetWithNoteAndTags(t *testing.T) {
	defer setup(t)()
	if _, e, c := lb("val_12345678\n", nil, "set", "K", "--stdin", "--note", "for tests", "--tag", "env:testnet", "--tag", "kind:token,owner:me"); c != 0 {
		t.Fatalf("%s", e)
	}
	j, _, _ := lb("", nil, "list", "--json")
	var m []struct {
		Key  string   `json:"key"`
		Note string   `json:"note"`
		Tags []string `json:"tags"`
	}
	if err := json.Unmarshal([]byte(j), &m); err != nil || len(m) != 1 || m[0].Note != "for tests" || strings.Join(m[0].Tags, ",") != "env:testnet,kind:token,owner:me" {
		t.Fatalf("meta: %v %s", err, j)
	}
	// re-setting the same value can still update metadata
	lb("val_12345678\n", nil, "set", "K", "--stdin", "--note", "updated note")
	if o, _, _ := lb("", nil, "note", "K"); strings.TrimSpace(o) != "updated note" {
		t.Fatalf("note not updated on unchanged set: %q", o)
	}
	// a new value keeps existing meta
	lb("", nil, "set", "K", "another_value_99")
	if o, _, _ := lb("", nil, "note", "K"); strings.TrimSpace(o) != "updated note" {
		t.Fatal("meta lost on value change")
	}
	// an invalid tag stops the whole set
	if _, _, c := lb("", nil, "set", "Z", "zzzzzzzzzzz", "--tag", "BAD TAG"); c == 0 {
		t.Fatal("bad tag accepted")
	}
	if _, _, c := lb("", nil, "get", "Z"); c == 0 {
		t.Fatal("secret stored despite bad tag")
	}
}

func TestListTagFilterAndVerbose(t *testing.T) {
	defer setup(t, "A", "va_12345678", "B", "vb_12345678", "C", "vc_12345678")()
	lb("", nil, "tag", "add", "A", "env:mainnet", "kind:wallet-key")
	lb("", nil, "tag", "add", "B", "env:mainnet")
	lb("", nil, "note", "A", "the main wallet")
	if o, _, c := lb("", nil, "list", "--tag", "env:mainnet"); c != 0 || strings.TrimSpace(o) != "A\nB" {
		t.Fatalf("one tag: %q", o)
	}
	if o, _, c := lb("", nil, "list", "--tag", "env:mainnet", "--tag", "kind:wallet-key"); c != 0 || strings.TrimSpace(o) != "A" {
		t.Fatalf("AND: %q", o)
	}
	if o, _, c := lb("", nil, "list", "--tag", "nope"); c != 1 || o != "" {
		t.Fatalf("no match: %d %q", c, o)
	}
	v, _, _ := lb("", nil, "list", "-v")
	lines := strings.Split(strings.TrimSpace(v), "\n")
	if len(lines) != 3 || !strings.Contains(lines[0], "env:mainnet kind:wallet-key") || !strings.Contains(lines[0], "the main wallet") {
		t.Fatalf("verbose A line: %q", v)
	}
	if !strings.Contains(lines[2], "-") { // C has no tags
		t.Fatalf("verbose C line: %q", lines[2])
	}
	if strings.Contains(v, "va_12345678") {
		t.Fatal("list -v leaked a value")
	}
	// plain list unchanged
	if o, _, _ := lb("", nil, "list"); strings.TrimSpace(o) != "A\nB\nC" {
		t.Fatalf("plain list: %q", o)
	}
}

func TestCheckShowsNoteAndTags(t *testing.T) {
	defer setup(t, "A", "va_12345678")()
	lb("", nil, "note", "A", "does a thing")
	lb("", nil, "tag", "add", "A", "env:testnet")
	o, _, _ := lb("", nil, "check", "A")
	if !strings.Contains(o, "  note: does a thing") || !strings.Contains(o, "  tags: env:testnet") {
		t.Fatalf("check: %q", o)
	}
	j, _, _ := lb("", nil, "check", "--json", "A")
	if !strings.Contains(j, `"note":"does a thing"`) || !strings.Contains(j, `"tags":["env:testnet"]`) {
		t.Fatalf("json: %s", j)
	}
}

func TestRunTagSelection(t *testing.T) {
	defer setup(t, "A", "va_12345678", "B", "vb_12345678", "C", "vc_12345678")()
	lb("", nil, "tag", "add", "A", "project:x", "env:testnet")
	lb("", nil, "tag", "add", "B", "project:x")
	out, e, c := lb("", nil, "run", "--tag", "project:x", "-c", `echo "$A $B ${C:-noc}"`)
	if c != 0 || strings.TrimSpace(out) != "va_12345678 vb_12345678 noc" {
		t.Fatalf("tag run: %q %q", out, e)
	}
	// AND semantics
	out, _, _ = lb("", nil, "run", "--tag", "project:x", "--tag", "env:testnet", "-c", `echo "$A ${B:-nob}"`)
	if strings.TrimSpace(out) != "va_12345678 nob" {
		t.Fatalf("AND: %q", out)
	}
	// combined with --only and --as
	out, _, _ = lb("", nil, "run", "--tag", "project:x", "--only", "C", "--as", "Z=A", "-c", `echo "$B $C $Z"`)
	if strings.TrimSpace(out) != "vb_12345678 vc_12345678 va_12345678" {
		t.Fatalf("combined: %q", out)
	}
	// an unknown tag fails closed, nothing runs
	if _, e, c := lb("", nil, "run", "--tag", "project:nope", "-c", "echo ran"); c == 0 || !strings.Contains(e, "no secrets tagged") {
		t.Fatalf("empty tag selection: %d %q", c, e)
	}
	// picked up at run time: tag a new key afterwards
	lb("", nil, "tag", "add", "C", "project:x")
	out, _, _ = lb("", nil, "run", "--tag", "project:x", "-c", `echo "$C"`)
	if strings.TrimSpace(out) != "vc_12345678" {
		t.Fatalf("late tag: %q", out)
	}
	if _, _, c := lb("", nil, "run", "--tag", "BAD TAG", "-c", "true"); c == 0 {
		t.Fatal("invalid tag accepted")
	}
}

func TestProfileWithTag(t *testing.T) {
	defer setup(t, "A", "va_12345678", "B", "vb_12345678")()
	lb("", nil, "tag", "add", "A", "project:x")
	if _, e, c := lb("", nil, "profile", "set", "px", "--tag", "project:x", "--redact"); c != 0 {
		t.Fatalf("%s", e)
	}
	out, _, c := lb("", nil, "run", "-p", "px", "-c", `echo "$A ${B:-nob}"`)
	if c != 0 || strings.TrimSpace(out) != "***A*** nob" {
		t.Fatalf("profile tag: %q", out)
	}
	lb("", nil, "tag", "add", "B", "project:x")
	out, _, _ = lb("", nil, "run", "-p", "px", "-c", `echo "$B"`)
	if strings.TrimSpace(out) != "***B***" {
		t.Fatalf("profile resolves tags at run time: %q", out)
	}
}

func TestProfileTagsCombineWithFlagTags(t *testing.T) {
	defer setup(t, "A", "va_12345678", "B", "vb_12345678", "C", "vc_12345678")()
	lb("", nil, "tag", "add", "A", "project:x")
	lb("", nil, "tag", "add", "B", "extra:y")
	lb("", nil, "profile", "set", "px", "--tag", "project:x")
	// profile tag AND flag tag are both required, so nothing carries both
	if _, e, c := lb("", nil, "run", "-p", "px", "--tag", "extra:y", "-c", "true"); c == 0 || !strings.Contains(e, "no secrets tagged") {
		t.Fatalf("flag tag ignored when a profile is used: %d %q", c, e)
	}
	lb("", nil, "tag", "add", "A", "extra:y")
	out, _, c := lb("", nil, "run", "-p", "px", "--tag", "extra:y", "-c", `echo "$A ${B:-nob}"`)
	if c != 0 || strings.TrimSpace(out) != "va_12345678 nob" {
		t.Fatalf("profile+flag tags: %q", out)
	}
}

func TestMetaSurvivesDeleteAndRollback(t *testing.T) {
	defer setup(t, "A", "va_12345678")()
	lb("", nil, "note", "A", "keep me")
	lb("", nil, "tag", "add", "A", "env:mainnet")
	lb("", nil, "delete", "A")
	if o, _, _ := lb("", nil, "list", "-v"); strings.Contains(o, "keep me") {
		t.Fatal("deleted key's metadata still listed")
	}
	if o, _, _ := lb("", nil, "tag", "list"); strings.Contains(o, "env:mainnet") {
		t.Fatal("deleted key counted in tag list")
	}
	lb("", nil, "rollback", "A")
	o, _, _ := lb("", nil, "check", "A")
	if !strings.Contains(o, "note: keep me") || !strings.Contains(o, "tags: env:mainnet") {
		t.Fatalf("meta not restored with the secret: %q", o)
	}
}

func TestRemoteMeta(t *testing.T) {
	defer setup(t, "A", "va_12345678", "B", "vb_12345678")()
	lb("", nil, "tag", "add", "A", "project:x")
	lb("", nil, "note", "A", "remote note")
	srv := exec.Command("./lockbox", "serve", "-p", "9893")
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	defer srv.Process.Kill()
	time.Sleep(600 * time.Millisecond)
	r := "127.0.0.1:9893"
	if o, _, c := lb("", nil, "list", "--remote", r, "--tag", "project:x", "-v"); c != 0 || !strings.Contains(o, "remote note") || strings.Contains(o, "\nB") {
		t.Fatalf("remote list: %q", o)
	}
	out, e, c := lb("", nil, "run", "--remote", r, "--tag", "project:x", "-c", `echo "$A ${B:-nob}"`)
	if c != 0 || strings.TrimSpace(out) != "va_12345678 nob" {
		t.Fatalf("remote tag run: %q %q", out, e)
	}
	if o, _, _ := lb("", nil, "check", "--remote", r, "A"); !strings.Contains(o, "note: remote note") {
		t.Fatalf("remote check: %q", o)
	}
	if _, e, c := lb("", nil, "run", "--remote", r, "--tag", "project:none", "-c", "true"); c == 0 || !strings.Contains(e, "no secrets tagged") {
		t.Fatalf("remote empty tag: %d %q", c, e)
	}
}

func TestOldServerWithoutMetaFallsBack(t *testing.T) {
	defer setup(t, "A", "va_12345678")()
	// a stand-in for an older server: /secrets works, /meta is 404
	srv := exec.Command("python3", "-I", "-c", `
import http.server,json
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(s):
        if s.path=="/secrets": s.send_response(200); s.end_headers(); s.wfile.write(json.dumps(["A"]).encode())
        elif s.path=="/secrets/A": s.send_response(200); s.end_headers(); s.wfile.write(b"va_12345678")
        else: s.send_response(404); s.end_headers()
    def log_message(*a): pass
http.server.HTTPServer(("127.0.0.1",9894),H).serve_forever()`)
	if err := srv.Start(); err != nil {
		t.Skip("python3 unavailable")
	}
	defer srv.Process.Kill()
	time.Sleep(600 * time.Millisecond)
	r := "127.0.0.1:9894"
	if o, _, c := lb("", nil, "list", "--remote", r, "-v"); c != 0 || !strings.Contains(o, "A") {
		t.Fatalf("list against old server: %d %q", c, o)
	}
	if _, e, c := lb("", nil, "run", "--remote", r, "--tag", "x", "-c", "true"); c == 0 || !strings.Contains(e, "does not support tags") {
		t.Fatalf("tag against old server: %d %q", c, e)
	}
	if o, _, c := lb("", nil, "run", "--remote", r, "--only", "A", "-c", "echo $A"); c != 0 || strings.TrimSpace(o) != "va_12345678" {
		t.Fatalf("--only against old server: %d %q", c, o)
	}
}
