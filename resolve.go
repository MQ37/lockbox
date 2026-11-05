package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/MQ37/lockbox/internal/crypto"
	"github.com/MQ37/lockbox/internal/db"
)

var envNameRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// scope says which secrets a command may see and under which names.
type scope struct {
	only   []string          // keys injected under their own name
	as     map[string]string // env name -> stored key
	tags   []string          // inject every key carrying ALL of these tags
	all    bool              // also inject every stored secret
	redact bool              // mask secret values in output
}

// scoped reports whether the caller asked for anything narrower than "all".
func (sc *scope) scoped() bool { return len(sc.only) > 0 || len(sc.as) > 0 || len(sc.tags) > 0 }

func splitList(vals []string) []string {
	var out []string
	for _, v := range vals {
		for _, p := range strings.Split(v, ",") {
			if p = strings.TrimSpace(p); p != "" {
				out = append(out, p)
			}
		}
	}
	return out
}

// parseAs parses NEW=OLD pairs.
func parseAs(vals []string) (map[string]string, error) {
	m := map[string]string{}
	for _, p := range splitList(vals) {
		i := strings.Index(p, "=")
		if i <= 0 || i == len(p)-1 {
			return nil, fmt.Errorf("invalid --as %q (want NEW_NAME=STORED_KEY)", p)
		}
		name, key := p[:i], p[i+1:]
		if !envNameRe.MatchString(name) {
			return nil, fmt.Errorf("invalid environment variable name %q in --as", name)
		}
		m[name] = key
	}
	return m, nil
}

// mergeScope adds b on top of a.
func mergeScope(a, b scope) scope {
	out := scope{as: map[string]string{}, all: a.all || b.all, redact: a.redact || b.redact}
	out.only = append(append([]string{}, a.only...), b.only...)
	out.tags = append(append([]string{}, a.tags...), b.tags...)
	for k, v := range a.as {
		out.as[k] = v
	}
	for k, v := range b.as {
		out.as[k] = v
	}
	return out
}

// secretSource fetches decrypted values by key, locally or from a remote server.
type secretSource interface {
	Keys() ([]string, error)
	Get(key string) (string, error)
	// Meta returns notes and tags by key. ok is false when the source cannot
	// provide them (an older remote server).
	Meta() (m map[string]db.Meta, ok bool, err error)
	Close()
}

type localSource struct {
	store *db.Store
	key   []byte
}

func openLocal() (*localSource, error) {
	store, key, err := getStoreAndKey()
	if err != nil {
		return nil, err
	}
	return &localSource{store, key}, nil
}
func (l *localSource) Close() { l.store.Close() }
func (l *localSource) Meta() (map[string]db.Meta, bool, error) {
	m, err := l.store.AllMeta()
	return m, err == nil, err
}
func (l *localSource) Keys() ([]string, error) { return l.store.ListSecrets() }
func (l *localSource) Get(key string) (string, error) {
	enc, err := l.store.GetSecret(key)
	if err != nil {
		return "", err
	}
	v, err := crypto.Decrypt(enc, l.key)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt secret '%s': %w", key, err)
	}
	return string(v), nil
}

type remoteSource struct{ addr string }

var remoteClient = &http.Client{Timeout: 30 * time.Second}

func (r remoteSource) Close() {}
func (r remoteSource) Meta() (map[string]db.Meta, bool, error) {
	resp, err := remoteClient.Get(fmt.Sprintf("http://%s/meta", r.addr))
	if err != nil {
		return nil, false, fmt.Errorf("failed to fetch metadata from remote: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, false, nil // older server without /meta
	}
	if resp.StatusCode != http.StatusOK {
		return nil, false, fmt.Errorf("remote server returned status %d for /meta", resp.StatusCode)
	}
	m := map[string]db.Meta{}
	if err := json.NewDecoder(resp.Body).Decode(&m); err != nil {
		return nil, false, fmt.Errorf("failed to decode remote metadata: %w", err)
	}
	return m, true, nil
}
func (r remoteSource) Keys() ([]string, error) {
	resp, err := remoteClient.Get(fmt.Sprintf("http://%s/secrets", r.addr))
	if err != nil {
		return nil, fmt.Errorf("failed to fetch secrets from remote: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("remote server returned status %d: %s", resp.StatusCode, body)
	}
	var keys []string
	if err := json.NewDecoder(resp.Body).Decode(&keys); err != nil {
		return nil, fmt.Errorf("failed to decode remote response: %w", err)
	}
	return keys, nil
}
func (r remoteSource) Get(key string) (string, error) {
	resp, err := remoteClient.Get(fmt.Sprintf("http://%s/secrets/%s", r.addr, url.PathEscape(key)))
	if err != nil {
		return "", fmt.Errorf("failed to fetch secret '%s' from remote: %w", key, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == http.StatusNotFound {
		return "", db.ErrNotFound
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("remote server returned status %d for '%s': %s", resp.StatusCode, key, body)
	}
	return string(body), nil
}

func newSource(remote string) (secretSource, error) {
	if remote != "" {
		return remoteSource{remote}, nil
	}
	return openLocal()
}

// resolved is the environment to inject plus the values to mask.
type resolved struct {
	env    map[string]string // env name -> value
	origin map[string]string // env name -> stored key it came from
}

// resolve turns a scope into concrete env values. Without scoping options it
// returns every stored secret (the historical behaviour). With --only/--as it
// returns exactly those, and fails before running anything if one is missing.
func resolve(src secretSource, sc scope) (*resolved, error) {
	r := &resolved{env: map[string]string{}, origin: map[string]string{}}
	add := func(name, key string) error {
		v, err := src.Get(key)
		if err != nil {
			if err == db.ErrNotFound {
				return fmt.Errorf("secret '%s' not found", key)
			}
			return err
		}
		r.env[name] = v
		r.origin[name] = key
		return nil
	}
	if !sc.scoped() || sc.all {
		keys, err := src.Keys()
		if err != nil {
			return nil, fmt.Errorf("failed to list secrets: %w", err)
		}
		for _, k := range keys {
			if err := add(k, k); err != nil {
				return nil, err
			}
		}
	}
	if len(sc.tags) > 0 {
		meta, ok, err := src.Meta()
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, fmt.Errorf("this server does not support tags (upgrade lockbox on the server host)")
		}
		matched := 0
		for key, m := range meta {
			if hasAllTags(m.Tags, sc.tags) {
				if err := add(key, key); err != nil {
					return nil, err
				}
				matched++
			}
		}
		if matched == 0 {
			return nil, fmt.Errorf("no secrets tagged %s", strings.Join(sc.tags, " + "))
		}
	}
	var missing []string
	for _, k := range sc.only {
		if err := add(k, k); err != nil {
			if strings.Contains(err.Error(), "not found") {
				missing = append(missing, k)
				continue
			}
			return nil, err
		}
	}
	names := make([]string, 0, len(sc.as))
	for n := range sc.as {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		if err := add(n, sc.as[n]); err != nil {
			if strings.Contains(err.Error(), "not found") {
				missing = append(missing, sc.as[n])
				continue
			}
			return nil, err
		}
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("secret(s) not found: %s", strings.Join(missing, ", "))
	}
	return r, nil
}

func fatal(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "Error: "+format+"\n", a...)
	os.Exit(1)
}

func hasAllTags(have, want []string) bool {
	set := map[string]bool{}
	for _, t := range have {
		set[t] = true
	}
	for _, t := range want {
		if !set[t] {
			return false
		}
	}
	return true
}

// normTags validates and lowercases a list of tags from flags.
func normTags(vals []string) ([]string, error) {
	var out []string
	for _, v := range splitList(vals) {
		t, err := db.NormalizeTag(v)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, nil
}
