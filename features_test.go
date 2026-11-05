package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"math/rand"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// lb runs ./lockbox with optional stdin and extra env.
func lb(stdin string, env []string, args ...string) (string, string, int) {
	cmd := exec.Command("./lockbox", args...)
	cmd.Env = append(os.Environ(), env...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	var o, e bytes.Buffer
	cmd.Stdout, cmd.Stderr = &o, &e
	err := cmd.Run()
	code := 0
	if err != nil {
		if x, ok := err.(*exec.ExitError); ok {
			code = x.ExitCode()
		} else {
			code = 127
		}
	}
	return o.String(), e.String(), code
}

func setup(t *testing.T, kv ...string) func() {
	_, cleanup := setupTest(t)
	if _, e, c := lb("", nil, "init"); c != 0 {
		t.Fatalf("init: %s", e)
	}
	for i := 0; i+1 < len(kv); i += 2 {
		if _, e, c := lb("", nil, "set", kv[i], kv[i+1]); c != 0 {
			t.Fatalf("set %s: %s", kv[i], e)
		}
	}
	return cleanup
}

// ---- run --only / --as / --all / profiles --------------------------------

func TestRunOnly(t *testing.T) {
	defer setup(t, "AAA", "val_a_12345", "BBB", "val_b_12345")()
	out, e, c := lb("", nil, "run", "--only", "AAA", "-c", `echo "A=$AAA B=${BBB:-none}"`)
	if c != 0 || strings.TrimSpace(out) != "A=val_a_12345 B=none" {
		t.Fatalf("got %q err %q code %d", out, e, c)
	}
	// short flag and comma list
	out, _, _ = lb("", nil, "run", "-o", "AAA,BBB", "-c", `echo "$AAA $BBB"`)
	if strings.TrimSpace(out) != "val_a_12345 val_b_12345" {
		t.Fatalf("comma list: %q", out)
	}
}

func TestRunUnscopedStillInjectsAll(t *testing.T) {
	defer setup(t, "AAA", "x1", "BBB", "x2")()
	out, _, _ := lb("", nil, "run", "-c", `echo "$AAA$BBB"`)
	if strings.TrimSpace(out) != "x1x2" {
		t.Fatalf("legacy behaviour broken: %q", out)
	}
}

func TestRunOnlyMissingAbortsBeforeRunning(t *testing.T) {
	defer setup(t, "AAA", "x1")()
	marker := "/tmp/lockbox-marker-" + time.Now().Format("150405.000000")
	defer os.Remove(marker)
	_, e, c := lb("", nil, "run", "--only", "AAA,NOPE,NOPE2", "-c", "touch "+marker)
	if c == 0 || !strings.Contains(e, "NOPE") || !strings.Contains(e, "NOPE2") {
		t.Fatalf("want failure naming missing keys, got code %d err %q", c, e)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("command ran despite missing secret")
	}
}

func TestRunAs(t *testing.T) {
	defer setup(t, "SRC_KEY", "0xkeyvalue", "OTHER", "other_value")()
	out, e, c := lb("", nil, "run", "--as", "PAYER_KEY=SRC_KEY", "-c",
		`echo "new=$PAYER_KEY old=${SRC_KEY:-unset} other=${OTHER:-unset}"`)
	if c != 0 || strings.TrimSpace(out) != "new=0xkeyvalue old=unset other=unset" {
		t.Fatalf("got %q err %q", out, e)
	}
	// bad forms
	for _, bad := range []string{"NOEQUALS", "=X", "X=", "1BAD=Y", "A B=Y"} {
		if _, _, c := lb("", nil, "run", "--as", bad, "-c", "true"); c == 0 {
			t.Errorf("--as %q should be rejected", bad)
		}
	}
	// missing stored key
	if _, e, c := lb("", nil, "run", "--as", "X=MISSING", "-c", "true"); c == 0 || !strings.Contains(e, "MISSING") {
		t.Errorf("missing stored key not reported: %d %q", c, e)
	}
}

func TestRunAllPlusAs(t *testing.T) {
	defer setup(t, "AAA", "x1", "BBB", "x2")()
	out, _, c := lb("", nil, "run", "--all", "--as", "CCC=AAA", "-c", `echo "$AAA $BBB $CCC"`)
	if c != 0 || strings.TrimSpace(out) != "x1 x2 x1" {
		t.Fatalf("got %q", out)
	}
}

func TestRunExitCodePropagates(t *testing.T) {
	defer setup(t, "AAA", "x1")()
	if _, _, c := lb("", nil, "run", "--only", "AAA", "--redact", "-c", "exit 7"); c != 7 {
		t.Fatalf("exit code %d", c)
	}
}

func TestProfiles(t *testing.T) {
	defer setup(t, "AAA", "secretvalue_aaa", "BBB", "secretvalue_bbb")()
	if _, e, c := lb("", nil, "profile", "set", "p1", "--only", "AAA", "--as", "ZZZ=BBB", "--redact"); c != 0 {
		t.Fatalf("profile set: %s", e)
	}
	out, _, _ := lb("", nil, "profile", "list")
	if strings.TrimSpace(out) != "p1" {
		t.Fatalf("list: %q", out)
	}
	show, _, _ := lb("", nil, "profile", "show", "p1")
	if strings.Contains(show, "secretvalue") {
		t.Fatal("profile show leaked a value")
	}
	// profile applies scope and redaction
	out, e, c := lb("", nil, "run", "-p", "p1", "-c", `echo "$AAA ${BBB:-nob} $ZZZ"`)
	if c != 0 || strings.TrimSpace(out) != "***AAA*** nob ***ZZZ***" {
		t.Fatalf("profile run: %q err %q", out, e)
	}
	// flags add on top
	out, _, _ = lb("", nil, "run", "-p", "p1", "--as", "QQQ=BBB", "-c", `echo "$QQQ"`)
	if strings.TrimSpace(out) != "***QQQ***" {
		t.Fatalf("flags on top of profile: %q", out)
	}
	if _, _, c := lb("", nil, "run", "-p", "nope", "-c", "true"); c == 0 {
		t.Fatal("unknown profile accepted")
	}
	if _, _, c := lb("", nil, "profile", "set", "empty"); c == 0 {
		t.Fatal("empty profile accepted")
	}
	if _, _, c := lb("", nil, "profile", "delete", "p1"); c != 0 {
		t.Fatal("delete failed")
	}
	if _, _, c := lb("", nil, "profile", "delete", "p1"); c == 0 {
		t.Fatal("delete of missing profile succeeded")
	}
	// profiles are not secrets
	if l, _, _ := lb("", nil, "list"); strings.Contains(l, "profile") {
		t.Fatalf("profile leaked into list: %q", l)
	}
}

// ---- redaction -----------------------------------------------------------

func TestRunRedact(t *testing.T) {
	v := "supersecretvalue123"
	defer setup(t, "TOK", v, "SHORT", "abc")()
	lb("-----BEGIN KEY-----\nlineone_of_the_key\nlinetwo_of_the_key\n-----END KEY-----\n", nil, "set", "PEM", "--stdin")
	script := `echo "raw=$TOK"; echo "err=$TOK" >&2; printf %s "$TOK" | base64 | sed 's/^/b64=/'; echo "short=$SHORT"; echo "$PEM"`
	out, errs, c := lb("", nil, "run", "--redact", "-c", script)
	if c != 0 {
		t.Fatalf("code %d %s", c, errs)
	}
	if strings.Contains(out+errs, v) || strings.Contains(out, base64.StdEncoding.EncodeToString([]byte(v))) {
		t.Fatalf("secret leaked:\n%s\n%s", out, errs)
	}
	if strings.Contains(out, "lineone_of_the_key") {
		t.Fatalf("multi-line value line leaked: %s", out)
	}
	for _, want := range []string{"raw=***TOK***", "b64=***TOK***", "short=abc"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in %q", want, out)
		}
	}
	if !strings.Contains(errs, "err=***TOK***") {
		t.Errorf("stderr not redacted: %q", errs)
	}
	// without --redact the value is untouched
	out, _, _ = lb("", nil, "run", "-c", `echo "$TOK"`)
	if strings.TrimSpace(out) != v {
		t.Fatalf("no-redact altered output: %q", out)
	}
	// env var turns it on
	out, _, _ = lb("", []string{"LOCKBOX_REDACT=1"}, "run", "-c", `echo "$TOK"`)
	if strings.TrimSpace(out) != "***TOK***" {
		t.Fatalf("LOCKBOX_REDACT ignored: %q", out)
	}
}

func TestRedactWriterChunkBoundaries(t *testing.T) {
	needles := buildNeedles(map[string]string{"ABC": "topsecret_token_value", "DEF": "another-secret-9999"})
	rnd := rand.New(rand.NewSource(1))
	for iter := 0; iter < 300; iter++ {
		var in strings.Builder
		for i := 0; i < 20+rnd.Intn(30); i++ {
			switch rnd.Intn(4) {
			case 0:
				in.WriteString("topsecret_token_value")
			case 1:
				in.WriteString("another-secret-9999")
			case 2:
				in.WriteString("topsecret_token") // partial prefix, must pass through
			default:
				in.WriteString(strings.Repeat("x", rnd.Intn(15)))
			}
		}
		src := in.String()
		want := strings.NewReplacer("topsecret_token_value", "***ABC***", "another-secret-9999", "***DEF***").Replace(src)
		var out bytes.Buffer
		w := newRedactWriter(&out, needles)
		for i := 0; i < len(src); {
			n := 1 + rnd.Intn(30)
			if i+n > len(src) {
				n = len(src) - i
			}
			w.Write([]byte(src[i : i+n]))
			i += n
		}
		w.Flush()
		if out.String() != want {
			t.Fatalf("iter %d:\n got  %q\n want %q", iter, out.String(), want)
		}
	}
}

func TestRedactWriterNoNeedlesPassesThrough(t *testing.T) {
	var out bytes.Buffer
	w := newRedactWriter(&out, buildNeedles(map[string]string{"A": "short"}))
	w.Write([]byte("hello short world"))
	w.Flush()
	if out.String() != "hello short world" {
		t.Fatalf("%q", out.String())
	}
}

// ---- has / check / list --------------------------------------------------

func TestHas(t *testing.T) {
	defer setup(t, "AAA", "x1", "BBB", "x2")()
	if o, e, c := lb("", nil, "has", "AAA", "BBB"); c != 0 || o != "" || e != "" {
		t.Fatalf("has ok: %d %q %q", c, o, e)
	}
	o, e, c := lb("", nil, "has", "AAA", "NOPE")
	if c != 1 || o != "" || !strings.Contains(e, "NOPE") || strings.Contains(e, "AAA") {
		t.Fatalf("has missing: %d %q %q", c, o, e)
	}
	lb("", nil, "set", "EMPTYK", "", "--allow-empty")
	if _, _, c := lb("", nil, "has", "EMPTYK"); c != 1 {
		t.Fatal("empty value counted as present")
	}
}

func TestCheck(t *testing.T) {
	evm := "0x" + strings.Repeat("ab", 32)
	defer setup(t, "EVM", evm, "BARE", strings.Repeat("cd", 32), "TOK", "ghp_ABCDEFGH12345", "URL", "mongodb://user:pw@host/db")()
	lb("\n", nil, "set", "NL", "--stdin", "--raw")
	lb("tokenvalue123\n", nil, "set", "NL2", "--stdin", "--raw")
	out, _, c := lb("", nil, "check", "EVM", "BARE", "TOK", "URL", "NL2")
	if c != 0 {
		t.Fatalf("code %d", c)
	}
	for _, leak := range []string{evm, "ABCDEFGH12345", "user:pw", "tokenvalue123"} {
		if strings.Contains(out, leak) {
			t.Fatalf("check leaked %q:\n%s", leak, out)
		}
	}
	for _, want := range []string{"EVM: set, length 66, 0x-hex, 32 bytes", "BARE: set, length 64, hex, 32 bytes WITHOUT 0x", "token (ghp_", "url (mongodb)", "ends with a newline"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in\n%s", want, out)
		}
	}
	jout, _, _ := lb("", nil, "check", "--json", "EVM", "MISSING")
	var res []checkResult
	if err := json.Unmarshal([]byte(jout), &res); err != nil || len(res) != 2 || !res[0].Set || res[1].Set {
		t.Fatalf("json: %v %q", err, jout)
	}
	if _, _, c := lb("", nil, "check", "MISSING"); c != 1 {
		t.Fatal("missing key should exit 1")
	}
}

func TestListGrepJSONVerbose(t *testing.T) {
	defer setup(t, "MAIN_WALLET_KEY", "x", "MAIN_ADDR", "y", "OTHER", "z")()
	out, _, c := lb("", nil, "list", "--grep", "main")
	if c != 0 || strings.TrimSpace(out) != "MAIN_ADDR\nMAIN_WALLET_KEY" {
		t.Fatalf("grep: %q", out)
	}
	if o, _, c := lb("", nil, "list", "--grep", "^other$"); c != 0 || strings.TrimSpace(o) != "OTHER" {
		t.Fatalf("regex grep: %q", o)
	}
	if o, _, c := lb("", nil, "list", "--grep", "nomatch"); c != 1 || o != "" {
		t.Fatalf("no match: %d %q", c, o)
	}
	j, _, _ := lb("", nil, "list", "--json")
	var m []map[string]string
	if err := json.Unmarshal([]byte(j), &m); err != nil || len(m) != 3 || m[0]["key"] != "MAIN_ADDR" || m[0]["updated_at"] == "" {
		t.Fatalf("json: %v %q", err, j)
	}
	if v, _, _ := lb("", nil, "list", "-v"); !strings.Contains(v, "MAIN_ADDR\t20") {
		t.Fatalf("verbose: %q", v)
	}
	if o, _, _ := lb("", nil, "list"); strings.TrimSpace(o) != "MAIN_ADDR\nMAIN_WALLET_KEY\nOTHER" {
		t.Fatalf("plain list changed: %q", o)
	}
}

// ---- set / history / rollback --------------------------------------------

func getv(t *testing.T, k string) string {
	o, e, c := lb("", nil, "get", k)
	if c != 0 {
		t.Fatalf("get %s: %s", k, e)
	}
	return o
}

func TestSetStdinFileTrimRaw(t *testing.T) {
	defer setup(t)()
	lb("tok123\n", nil, "set", "A", "--stdin")
	if getv(t, "A") != "tok123" {
		t.Fatalf("stdin newline not stripped: %q", getv(t, "A"))
	}
	lb("tok123\r\n", nil, "set", "B", "--stdin")
	if getv(t, "B") != "tok123" {
		t.Fatalf("CRLF not stripped: %q", getv(t, "B"))
	}
	lb("tok123\n", nil, "set", "C", "--stdin", "--raw")
	if getv(t, "C") != "tok123\n" {
		t.Fatalf("raw altered: %q", getv(t, "C"))
	}
	lb("  \ttok123 \n\n", nil, "set", "D", "--stdin", "--trim")
	if getv(t, "D") != "tok123" {
		t.Fatalf("trim: %q", getv(t, "D"))
	}
	f := "/tmp/lockbox-val-" + time.Now().Format("150405.000000")
	os.WriteFile(f, []byte("filevalue\n"), 0600)
	defer os.Remove(f)
	lb("", nil, "set", "E", "--file", f)
	if getv(t, "E") != "filevalue" {
		t.Fatalf("file: %q", getv(t, "E"))
	}
	lb("", nil, "set", "F", "  arg  ", "--trim")
	if getv(t, "F") != "arg" {
		t.Fatalf("arg trim: %q", getv(t, "F"))
	}
	// legacy argv form is byte-exact
	lb("", nil, "set", "G", "legacy\n")
	if getv(t, "G") != "legacy\n" {
		t.Fatalf("legacy argv changed: %q", getv(t, "G"))
	}
	// multi-line values survive
	lb("l1\nl2\n", nil, "set", "H", "--stdin")
	if getv(t, "H") != "l1\nl2" {
		t.Fatalf("multiline: %q", getv(t, "H"))
	}
}

func TestSetSourceValidation(t *testing.T) {
	defer setup(t)()
	for _, args := range [][]string{
		{"set", "K"},                           // no source
		{"set", "K", "v", "--stdin"},           // two sources
		{"set", "K", "--file", "/nonexistent"}, // unreadable
	} {
		if _, _, c := lb("x", nil, args...); c == 0 {
			t.Errorf("%v should fail", args)
		}
	}
}

func TestSetRefusesEmpty(t *testing.T) {
	defer setup(t, "K", "orig")()
	for _, in := range []struct {
		stdin string
		args  []string
	}{{"", []string{"set", "K", ""}}, {"\n", []string{"set", "K", "--stdin"}}, {"  \n", []string{"set", "K", "--stdin", "--trim"}}} {
		if _, e, c := lb(in.stdin, nil, in.args...); c == 0 || !strings.Contains(e, "empty") {
			t.Errorf("%v: want empty refusal, got code %d %q", in.args, c, e)
		}
	}
	if getv(t, "K") != "orig" {
		t.Fatal("failed set clobbered the secret")
	}
	if _, _, c := lb("", nil, "set", "K", "", "--allow-empty"); c != 0 {
		t.Fatal("--allow-empty refused")
	}
}

func TestNoOverwrite(t *testing.T) {
	defer setup(t, "K", "orig")()
	if _, e, c := lb("", nil, "set", "K", "new", "--no-overwrite"); c == 0 || !strings.Contains(e, "exists") {
		t.Fatalf("overwrite not refused: %d %q", c, e)
	}
	if getv(t, "K") != "orig" {
		t.Fatal("value changed")
	}
	if _, _, c := lb("", nil, "set", "NEWK", "v", "--no-overwrite"); c != 0 {
		t.Fatal("--no-overwrite on a new key failed")
	}
}

func TestHistoryRollback(t *testing.T) {
	defer setup(t, "K", "v1")()
	out, _, _ := lb("", nil, "set", "K", "v2")
	if !strings.Contains(out, "rollback") {
		t.Errorf("no rollback hint: %q", out)
	}
	if o, _, _ := lb("", nil, "set", "K", "v2"); !strings.Contains(o, "unchanged") {
		t.Errorf("same value not reported unchanged: %q", o)
	}
	lb("", nil, "set", "K", "v3")
	if h, _, _ := lb("", nil, "history", "K"); strings.Count(h, "replaced at") != 2 {
		t.Fatalf("history: %q", h)
	}
	if _, _, c := lb("", nil, "rollback", "K"); c != 0 || getv(t, "K") != "v2" {
		t.Fatalf("rollback to v2 got %q", getv(t, "K"))
	}
	// rollback is undoable: the replaced value (v3) is now in history
	lb("", nil, "rollback", "K") // -> v3 again? newest history is v3
	if getv(t, "K") != "v3" {
		t.Fatalf("second rollback: %q", getv(t, "K"))
	}
	if _, e, c := lb("", nil, "rollback", "NOHISTORY"); c == 0 || !strings.Contains(e, "no previous") {
		t.Fatalf("rollback of unknown key: %d %q", c, e)
	}
}

func TestHistoryLimit(t *testing.T) {
	defer setup(t, "K", "v0")()
	for i := 1; i <= 9; i++ {
		lb("", nil, "set", "K", "v"+string(rune('0'+i)))
	}
	if h, _, _ := lb("", nil, "history", "K"); strings.Count(h, "replaced at") != 5 {
		t.Fatalf("history not capped at 5: %q", h)
	}
}

func TestDeleteIsRecoverable(t *testing.T) {
	defer setup(t, "K", "precious")()
	lb("", nil, "delete", "K")
	if _, _, c := lb("", nil, "get", "K"); c == 0 {
		t.Fatal("delete did not delete")
	}
	if _, _, c := lb("", nil, "rollback", "K"); c != 0 || getv(t, "K") != "precious" {
		t.Fatal("rollback after delete failed")
	}
}

// ---- misc ----------------------------------------------------------------

func TestDBFileIsPrivate(t *testing.T) {
	dbPath, cleanup := setupTest(t)
	defer cleanup()
	lb("", nil, "init")
	st, err := os.Stat(dbPath)
	if err != nil || st.Mode().Perm() != 0600 {
		t.Fatalf("db mode %v err %v", st.Mode().Perm(), err)
	}
}

func TestLearnIsEnvironmentAware(t *testing.T) {
	host, _, _ := lb("", []string{"LOCKBOX_LEARN=host"}, "learn")
	if !strings.Contains(host, "--only") || !strings.Contains(host, "lockbox has") || strings.Contains(host, "host.containers.internal") {
		t.Fatal("host learn text wrong")
	}
	ctr, _, _ := lb("", []string{"LOCKBOX_LEARN=container"}, "learn")
	if !strings.Contains(ctr, "host.containers.internal:8100") || !strings.Contains(ctr, "--only") {
		t.Fatal("container learn text wrong")
	}
	// every command line in learn must be a real flag/command
	for _, s := range []string{"lockbox list --grep", "lockbox check", "profile set", "rollback"} {
		if !strings.Contains(host, s) {
			t.Errorf("learn lacks %q", s)
		}
	}
}

func TestVersion(t *testing.T) {
	if o, _, c := lb("", nil, "--version"); c != 0 || !strings.Contains(o, "lockbox version") {
		t.Fatalf("%d %q", c, o)
	}
}

func TestRemoteScopedFeatures(t *testing.T) {
	defer setup(t, "AAA", "remote_aaa_value", "BBB", "remote_bbb_value", "WALLET_X", "w")()
	srv := exec.Command("./lockbox", "serve", "-p", "9891")
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	defer srv.Process.Kill()
	time.Sleep(600 * time.Millisecond)
	r := "127.0.0.1:9891"
	out, e, c := lb("", nil, "run", "--remote", r, "--only", "AAA", "-c", `echo "$AAA ${BBB:-nob}"`)
	if c != 0 || strings.TrimSpace(out) != "remote_aaa_value nob" {
		t.Fatalf("remote only: %q %q", out, e)
	}
	out, _, c = lb("", nil, "run", "--remote", r, "--as", "XX=BBB", "--redact", "-c", `echo "$XX"`)
	if c != 0 || strings.TrimSpace(out) != "***XX***" {
		t.Fatalf("remote as/redact: %q", out)
	}
	if _, e, c := lb("", nil, "run", "--remote", r, "--only", "NOPE", "-c", "true"); c == 0 || !strings.Contains(e, "NOPE") {
		t.Fatalf("remote missing: %d %q", c, e)
	}
	if o, _, c := lb("", nil, "list", "--remote", r, "--grep", "wallet"); c != 0 || strings.TrimSpace(o) != "WALLET_X" {
		t.Fatalf("remote list: %q", o)
	}
	if _, _, c := lb("", nil, "has", "--remote", r, "AAA", "BBB"); c != 0 {
		t.Fatal("remote has")
	}
	if _, _, c := lb("", nil, "has", "--remote", r, "NOPE"); c != 1 {
		t.Fatal("remote has missing")
	}
	if o, _, _ := lb("", nil, "check", "--remote", r, "AAA"); !strings.Contains(o, "AAA: set, length 16") {
		t.Fatalf("remote check: %q", o)
	}
}
