package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/MQ37/lockbox/internal/crypto"
	"github.com/MQ37/lockbox/internal/db"
	"github.com/spf13/cobra"
)

// ---- set -----------------------------------------------------------------

func newSetCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "set KEY [VALUE]",
		Short: "Set a secret",
		Long: `Store a secret. The value comes from exactly one of: the VALUE argument,
--stdin, or --file. Prefer --stdin or --file: a value on the command line
shows up in the process list and in shell history.

  printf %s "$TOKEN" | lockbox set API_KEY --stdin
  lockbox set API_KEY --file /dev/shm/token.txt

Input from --stdin/--file loses one trailing newline (--raw keeps it).
--trim strips all surrounding whitespace from any source. An empty value is
refused unless --allow-empty, so a failed pipeline cannot blank a secret.

Setting an existing key keeps the previous value; "lockbox rollback KEY"
restores it (the last 5 values are kept). --no-overwrite refuses instead.

--note TEXT and --tag T attach a one-line note and tags (plaintext, see
"lockbox note --help" and "lockbox tag --help"); text containing a secret
value is refused.`,
		Args: cobra.RangeArgs(1, 2),
		Run: func(cmd *cobra.Command, args []string) {
			key := args[0]
			useStdin, _ := cmd.Flags().GetBool("stdin")
			file, _ := cmd.Flags().GetString("file")
			trim, _ := cmd.Flags().GetBool("trim")
			raw, _ := cmd.Flags().GetBool("raw")
			noOver, _ := cmd.Flags().GetBool("no-overwrite")
			allowEmpty, _ := cmd.Flags().GetBool("allow-empty")
			var note *string
			if cmd.Flags().Changed("note") {
				n, _ := cmd.Flags().GetString("note")
				note = &n
			}
			tagRaw, _ := cmd.Flags().GetStringArray("tag")
			tags, err := normTags(tagRaw)
			if err != nil {
				fatal("%v", err)
			}

			sources := 0
			if len(args) == 2 {
				sources++
			}
			if useStdin {
				sources++
			}
			if file != "" {
				sources++
			}
			if sources != 1 {
				fatal("provide the value as exactly one of: VALUE argument, --stdin, --file")
			}
			var value string
			switch {
			case len(args) == 2:
				value = args[1]
			case useStdin:
				b, err := io.ReadAll(os.Stdin)
				if err != nil {
					fatal("failed to read stdin: %v", err)
				}
				value = string(b)
			default:
				b, err := os.ReadFile(file)
				if err != nil {
					fatal("failed to read %s: %v", file, err)
				}
				value = string(b)
			}
			if len(args) < 2 && !raw {
				value = strings.TrimSuffix(strings.TrimSuffix(value, "\n"), "\r")
			}
			if trim {
				value = strings.TrimSpace(value)
			}
			if value == "" && !allowEmpty {
				fatal("refusing to store an empty value for '%s' (use --allow-empty to force)", key)
			}

			store, encKey, err := getStoreAndKey()
			if err != nil {
				fatal("%v", err)
			}
			defer store.Close()

			existed, err := store.HasSecret(key)
			if err != nil {
				fatal("%v", err)
			}
			if existed {
				if noOver {
					fatal("secret '%s' already exists (--no-overwrite)", key)
				}
				if oldEnc, err := store.GetSecret(key); err == nil {
					if old, err := crypto.Decrypt(oldEnc, encKey); err == nil && string(old) == value {
						if err := applyMeta(store, encKey, key, note, tags, value); err != nil {
							fatal("%v", err)
						}
						fmt.Printf("✓ Secret '%s' unchanged\n", key)
						return
					}
				}
			}
			if note != nil || len(tags) > 0 {
				// validate before storing so a refused note cannot leave a half-done set
				texts := append([]string{}, tags...)
				if note != nil {
					if err := db.ValidateNote(*note); err != nil {
						fatal("%v", err)
					}
					texts = append(texts, *note)
				}
				if err := guardText(store, encKey, value, texts...); err != nil {
					fatal("%v", err)
				}
			}
			enc, err := crypto.Encrypt([]byte(value), encKey)
			if err != nil {
				fatal("failed to encrypt value: %v", err)
			}
			if err := store.SetSecret(key, enc); err != nil {
				fatal("failed to store secret: %v", err)
			}
			if err := applyMeta(store, encKey, key, note, tags, value); err != nil {
				fatal("secret stored, but the note/tags were not: %v", err)
			}
			fmt.Printf("✓ Secret '%s' set successfully\n", key)
			if existed {
				fmt.Printf("  previous value kept; undo with: lockbox rollback %s\n", key)
			}
		},
	}
	c.Flags().Bool("stdin", false, "read the value from standard input")
	c.Flags().StringP("file", "f", "", "read the value from a file")
	c.Flags().Bool("trim", false, "strip all leading and trailing whitespace")
	c.Flags().Bool("raw", false, "keep --stdin/--file input exactly (no newline strip)")
	c.Flags().Bool("no-overwrite", false, "fail if the key already exists")
	c.Flags().Bool("allow-empty", false, "allow storing an empty value")
	c.Flags().String("note", "", "one-line note saying what the secret is for (plaintext!)")
	c.Flags().StringArray("tag", nil, "tag to add (repeatable), e.g. env:mainnet")
	return c
}

func newHistoryCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "history KEY",
		Short: "Show how many previous values of a secret are kept",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			store, _, err := getStoreAndKey()
			if err != nil {
				fatal("%v", err)
			}
			defer store.Close()
			h, err := store.History(args[0])
			if err != nil {
				fatal("%v", err)
			}
			if len(h) == 0 {
				fmt.Println("No previous values")
				return
			}
			for i, e := range h {
				fmt.Printf("%d  replaced at %s UTC\n", i+1, e.ReplacedAt)
			}
		},
	}
}

func newRollbackCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "rollback KEY",
		Short: "Restore the previous value of a secret (also undoes a delete)",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			store, _, err := getStoreAndKey()
			if err != nil {
				fatal("%v", err)
			}
			defer store.Close()
			if err := store.Rollback(args[0]); err != nil {
				if err == db.ErrNotFound {
					fatal("no previous value kept for '%s'", args[0])
				}
				fatal("%v", err)
			}
			fmt.Printf("✓ Secret '%s' rolled back\n", args[0])
		},
	}
}

// ---- list ----------------------------------------------------------------

func newListCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "list",
		Short: "List all secrets",
		Long: `Display stored secret keys (never values).

  lockbox list                     one key per line
  lockbox list -v                  key, tags, last-updated date and note
  lockbox list --grep wallet       only keys matching a case-insensitive pattern
  lockbox list --tag env:mainnet   only keys carrying the tag (repeat: all must match)
  lockbox list --json              [{"key","created_at","updated_at","note","tags"}]

With --grep/--tag and no match nothing is printed and the exit code is 1.`,
		Args: cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			remote, _ := cmd.Flags().GetString("remote")
			grep, _ := cmd.Flags().GetString("grep")
			asJSON, _ := cmd.Flags().GetBool("json")
			verbose, _ := cmd.Flags().GetBool("verbose")
			tagRaw, _ := cmd.Flags().GetStringArray("tag")
			wantTags, err := normTags(tagRaw)
			if err != nil {
				fatal("%v", err)
			}

			var metas []db.SecretMeta
			if remote != "" {
				src := remoteSource{remote}
				keys, err := src.Keys()
				if err != nil {
					fatal("%v", err)
				}
				rm, ok, err := src.Meta()
				if err != nil {
					fatal("%v", err)
				}
				if !ok && len(wantTags) > 0 {
					fatal("this server does not support tags (upgrade lockbox on the server host)")
				}
				for _, k := range keys {
					m := db.SecretMeta{Key: k, Note: rm[k].Note, Tags: rm[k].Tags}
					if m.Tags == nil {
						m.Tags = []string{}
					}
					metas = append(metas, m)
				}
			} else {
				store, _, err := getStoreAndKey()
				if err != nil {
					fatal("%v", err)
				}
				defer store.Close()
				if metas, err = store.ListSecretMeta(); err != nil {
					fatal("failed to list secrets: %v", err)
				}
			}
			filtered := grep != "" || len(wantTags) > 0
			if grep != "" {
				match := func(s string) bool { return strings.Contains(strings.ToLower(s), strings.ToLower(grep)) }
				if re, err := regexp.Compile("(?i)" + grep); err == nil {
					match = re.MatchString
				}
				var f []db.SecretMeta
				for _, m := range metas {
					if match(m.Key) {
						f = append(f, m)
					}
				}
				metas = f
			}
			if len(wantTags) > 0 {
				var f []db.SecretMeta
				for _, m := range metas {
					if hasAllTags(m.Tags, wantTags) {
						f = append(f, m)
					}
				}
				metas = f
			}
			if asJSON {
				if metas == nil {
					metas = []db.SecretMeta{}
				}
				b, _ := json.Marshal(metas)
				fmt.Println(string(b))
				if len(metas) == 0 && filtered {
					os.Exit(1)
				}
				return
			}
			if len(metas) == 0 {
				if filtered {
					os.Exit(1)
				}
				fmt.Println("No secrets found")
				return
			}
			if verbose {
				tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
				for _, m := range metas {
					tags := strings.Join(m.Tags, " ")
					if tags == "" {
						tags = "-"
					}
					date := "-"
					if len(m.UpdatedAt) >= 10 {
						date = m.UpdatedAt[:10]
					}
					fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", m.Key, tags, date, m.Note)
				}
				tw.Flush()
				return
			}
			for _, m := range metas {
				fmt.Println(m.Key)
			}
		},
	}
	c.Flags().StringP("remote", "r", "", "Remote server to read from (e.g., localhost:8100)")
	c.Flags().String("grep", "", "only keys matching this case-insensitive pattern")
	c.Flags().StringArray("tag", nil, "only keys carrying this tag (repeat: all must match)")
	c.Flags().Bool("json", false, "machine-readable output")
	c.Flags().BoolP("verbose", "v", false, "show tags, last-updated date and note")
	return c
}

// ---- has / check ---------------------------------------------------------

func newHasCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "has KEY...",
		Short: "Exit 0 if every KEY exists and is non-empty (prints nothing)",
		Long: `Check that secrets exist without reading them. Exit code 0 means all of the
given keys exist and have a non-empty value; 1 means at least one does not
(the missing names go to stderr).

  lockbox has API_TOKEN MAIN_WALLET_KEY && echo ready`,
		Args: cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			remote, _ := cmd.Flags().GetString("remote")
			src, err := newSource(remote)
			if err != nil {
				fatal("%v", err)
			}
			defer src.Close()
			var bad []string
			for _, k := range args {
				v, err := src.Get(k)
				if err != nil && err != db.ErrNotFound {
					fatal("%v", err)
				}
				if err != nil || v == "" {
					bad = append(bad, k)
				}
			}
			if len(bad) > 0 {
				fmt.Fprintf(os.Stderr, "missing or empty: %s\n", strings.Join(bad, ", "))
				os.Exit(1)
			}
		},
	}
	c.Flags().StringP("remote", "r", "", "Remote server to read from (e.g., localhost:8100)")
	return c
}

type checkResult struct {
	Key       string   `json:"key"`
	Set       bool     `json:"set"`
	Length    int      `json:"length,omitempty"`
	Class     string   `json:"class,omitempty"`
	Warnings  []string `json:"warnings,omitempty"`
	UpdatedAt string   `json:"updated_at,omitempty"`
	Note      string   `json:"note,omitempty"`
	Tags      []string `json:"tags,omitempty"`
}

var (
	hexRe    = regexp.MustCompile(`^[0-9a-fA-F]+$`)
	b58Re    = regexp.MustCompile(`^[1-9A-HJ-NP-Za-km-z]+$`)
	urlRe    = regexp.MustCompile(`^([a-zA-Z][a-zA-Z0-9+.-]*)://`)
	b64Re    = regexp.MustCompile(`^[A-Za-z0-9+/_-]+=*$`)
	knownPfx = []string{"sk-ant-", "sk-or-", "sk-", "ghp_", "gho_", "github_pat_", "npm_", "pypi-", "apify_api_", "xoxb-", "xoxp-", "AKIA", "rubygems_"}
)

// classify describes the shape of a value without revealing it: a fixed
// vocabulary only, never a slice of the value itself (known vendor prefixes
// and URL schemes are public, not secret).
func classify(v string) string {
	switch {
	case strings.Contains(v, "-----BEGIN "):
		return "pem"
	case urlRe.MatchString(v):
		return "url (" + strings.ToLower(urlRe.FindStringSubmatch(v)[1]) + ")"
	case strings.HasPrefix(v, "0x") && len(v) == 66 && hexRe.MatchString(v[2:]):
		return "0x-hex, 32 bytes (EVM private key shape)"
	case strings.HasPrefix(v, "0x") && len(v) == 42 && hexRe.MatchString(v[2:]):
		return "0x-hex, 20 bytes (EVM address shape)"
	case strings.HasPrefix(v, "0x") && hexRe.MatchString(v[2:]):
		return "0x-hex"
	case len(v) == 64 && hexRe.MatchString(v):
		return "hex, 32 bytes WITHOUT 0x prefix"
	case hexRe.MatchString(v) && len(v) >= 16:
		return "hex"
	case strings.Count(v, ".") == 2 && b64Re.MatchString(strings.ReplaceAll(v, ".", "")):
		return "jwt-like"
	}
	for _, p := range knownPfx {
		if strings.HasPrefix(v, p) {
			return "token (" + p + "…)"
		}
	}
	if len(v) >= 86 && len(v) <= 90 && b58Re.MatchString(v) {
		return "base58, Solana secret key length"
	}
	if len(v) >= 32 && len(v) <= 44 && b58Re.MatchString(v) {
		return "base58, Solana address/pubkey length"
	}
	if b64Re.MatchString(v) && len(v) >= 24 {
		return "base64-like"
	}
	return "text"
}

func inspect(key, v string) checkResult {
	r := checkResult{Key: key, Set: v != "", Length: len(v)}
	if v == "" {
		return r
	}
	r.Class = classify(v)
	if strings.HasSuffix(v, "\n") || strings.HasSuffix(v, "\r") {
		r.Warnings = append(r.Warnings, "ends with a newline")
	}
	if strings.TrimSpace(v) != strings.Trim(v, "\r\n") {
		r.Warnings = append(r.Warnings, "has leading/trailing spaces")
	}
	if strings.ContainsAny(strings.TrimRight(v, "\r\n"), "\r\n") && r.Class != "pem" {
		r.Warnings = append(r.Warnings, "multi-line")
	}
	if strings.ContainsAny(v, "\x00") {
		r.Warnings = append(r.Warnings, "contains NUL")
	}
	return r
}

func newCheckCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "check KEY...",
		Short: "Describe a secret without revealing it (length, shape, warnings)",
		Long: `Report whether each secret is set, its length, a coarse shape class (for
example "0x-hex, 32 bytes (EVM private key shape)"), when it was last updated,
and warnings such as a trailing newline. The value itself is never printed.

The note and tags (see "lockbox note --help") are shown too.
Exit code 1 if any key is missing or empty.`,
		Args: cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			remote, _ := cmd.Flags().GetString("remote")
			asJSON, _ := cmd.Flags().GetBool("json")
			src, err := newSource(remote)
			if err != nil {
				fatal("%v", err)
			}
			defer src.Close()
			var results []checkResult
			meta, _, err := src.Meta()
			if err != nil {
				fatal("%v", err)
			}
			bad := false
			for _, k := range args {
				v, err := src.Get(k)
				if err != nil && err != db.ErrNotFound {
					fatal("%v", err)
				}
				r := inspect(k, v)
				if err == nil {
					r.Note, r.Tags = meta[k].Note, meta[k].Tags
					if l, ok := src.(*localSource); ok {
						if m, e := l.store.SecretInfo(k); e == nil {
							r.UpdatedAt = m.UpdatedAt
						}
					}
				}
				if !r.Set {
					bad = true
				}
				results = append(results, r)
			}
			if asJSON {
				b, _ := json.Marshal(results)
				fmt.Println(string(b))
			} else {
				for _, r := range results {
					if !r.Set {
						fmt.Printf("%s: MISSING or empty\n", r.Key)
						continue
					}
					line := fmt.Sprintf("%s: set, length %d, %s", r.Key, r.Length, r.Class)
					if r.UpdatedAt != "" {
						line += ", updated " + r.UpdatedAt + " UTC"
					}
					if len(r.Warnings) > 0 {
						line += "  [warning: " + strings.Join(r.Warnings, "; ") + "]"
					}
					fmt.Println(line)
					if r.Note != "" {
						fmt.Println("  note: " + r.Note)
					}
					if len(r.Tags) > 0 {
						fmt.Println("  tags: " + strings.Join(r.Tags, " "))
					}
				}
			}
			if bad {
				os.Exit(1)
			}
		},
	}
	c.Flags().StringP("remote", "r", "", "Remote server to read from (e.g., localhost:8100)")
	c.Flags().Bool("json", false, "machine-readable output")
	return c
}

// ---- profiles ------------------------------------------------------------

type profile struct {
	Only   []string          `json:"only,omitempty"`
	Tags   []string          `json:"tags,omitempty"`
	As     map[string]string `json:"as,omitempty"`
	All    bool              `json:"all,omitempty"`
	Redact bool              `json:"redact,omitempty"`
}

const profilePrefix = "profile:"

func loadProfile(name string) (scope, error) {
	store, _, err := getStoreAndKey()
	if err != nil {
		return scope{}, err
	}
	defer store.Close()
	raw, err := store.GetConfig(profilePrefix + name)
	if err != nil {
		if err == db.ErrNotFound {
			return scope{}, fmt.Errorf("profile '%s' not found (see: lockbox profile list)", name)
		}
		return scope{}, err
	}
	var p profile
	if err := json.Unmarshal(raw, &p); err != nil {
		return scope{}, fmt.Errorf("profile '%s' is corrupt: %w", name, err)
	}
	return scope{only: p.Only, tags: p.Tags, as: p.As, all: p.All, redact: p.Redact}, nil
}

func newProfileCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "profile",
		Short: "Named allow-lists of secrets for 'lockbox run -p NAME'",
		Long: `A profile is a saved set of --only/--as options (key names only, no values),
so a project always gets exactly the secrets it is meant to see:

  lockbox profile set myapp --only MAIN_WALLET_KEY,BACKUP_WALLET_KEY \
      --as PAYER_KEY=MAIN_WALLET_KEY --redact
  lockbox run -p myapp -- go test ./...`,
	}
	set := &cobra.Command{
		Use:   "set NAME",
		Short: "Create or replace a profile",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			only, _ := cmd.Flags().GetStringArray("only")
			asRaw, _ := cmd.Flags().GetStringArray("as")
			tagRaw, _ := cmd.Flags().GetStringArray("tag")
			all, _ := cmd.Flags().GetBool("all")
			redact, _ := cmd.Flags().GetBool("redact")
			as, err := parseAs(asRaw)
			if err != nil {
				fatal("%v", err)
			}
			tags, err := normTags(tagRaw)
			if err != nil {
				fatal("%v", err)
			}
			p := profile{Only: splitList(only), Tags: tags, As: as, All: all, Redact: redact}
			if len(p.Only) == 0 && len(p.As) == 0 && len(p.Tags) == 0 && !p.All {
				fatal("a profile needs --only, --as and/or --tag (or --all)")
			}
			store, _, err := getStoreAndKey()
			if err != nil {
				fatal("%v", err)
			}
			defer store.Close()
			b, _ := json.Marshal(p)
			if err := store.SetConfig(profilePrefix+args[0], b); err != nil {
				fatal("%v", err)
			}
			fmt.Printf("✓ Profile '%s' saved\n", args[0])
		},
	}
	set.Flags().StringArray("only", nil, "keys to inject under their own name (comma-separated, repeatable)")
	set.Flags().StringArray("as", nil, "NEW_NAME=STORED_KEY renames (comma-separated, repeatable)")
	set.Flags().StringArray("tag", nil, "inject every key carrying this tag, resolved at run time (repeat: all must match)")
	set.Flags().Bool("all", false, "also inject every stored secret")
	set.Flags().Bool("redact", false, "mask secret values in output")
	list := &cobra.Command{
		Use:   "list",
		Short: "List profile names",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			store, _, err := getStoreAndKey()
			if err != nil {
				fatal("%v", err)
			}
			defer store.Close()
			m, err := store.ListConfig(profilePrefix)
			if err != nil {
				fatal("%v", err)
			}
			var names []string
			for k := range m {
				names = append(names, strings.TrimPrefix(k, profilePrefix))
			}
			sort.Strings(names)
			for _, n := range names {
				fmt.Println(n)
			}
		},
	}
	show := &cobra.Command{
		Use:   "show NAME",
		Short: "Show a profile (key names only)",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			store, _, err := getStoreAndKey()
			if err != nil {
				fatal("%v", err)
			}
			defer store.Close()
			raw, err := store.GetConfig(profilePrefix + args[0])
			if err != nil {
				fatal("profile '%s' not found", args[0])
			}
			fmt.Println(string(raw))
		},
	}
	del := &cobra.Command{
		Use:   "delete NAME",
		Short: "Delete a profile",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			store, _, err := getStoreAndKey()
			if err != nil {
				fatal("%v", err)
			}
			defer store.Close()
			if err := store.DeleteConfig(profilePrefix + args[0]); err != nil {
				fatal("profile '%s' not found", args[0])
			}
			fmt.Printf("✓ Profile '%s' deleted\n", args[0])
		},
	}
	root.AddCommand(set, list, show, del)
	return root
}
