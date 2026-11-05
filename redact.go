package main

import (
	"bytes"
	"encoding/base64"
	"io"
	"net/url"
	"sort"
	"strings"
)

// minRedactLen is the shortest secret value that gets masked; shorter values
// (like "1" or "true") would shred ordinary output.
const minRedactLen = 8

type needle struct {
	pat   []byte
	label string
}

// buildNeedles returns the byte patterns to mask, longest first. For each
// secret it covers the raw value, each non-trivial line of a multi-line value,
// and the base64 and URL-escaped forms.
func buildNeedles(values map[string]string) []needle {
	seen := map[string]bool{}
	var out []needle
	add := func(p, label string) {
		if len(p) < minRedactLen || seen[p] {
			return
		}
		seen[p] = true
		out = append(out, needle{[]byte(p), label})
	}
	names := make([]string, 0, len(values))
	for n := range values {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		v := values[n]
		label := "***" + n + "***"
		add(v, label)
		if strings.ContainsAny(v, "\r\n") {
			for _, line := range strings.FieldsFunc(v, func(r rune) bool { return r == '\n' || r == '\r' }) {
				add(strings.TrimSpace(line), label)
			}
		}
		if len(v) >= minRedactLen {
			add(base64.StdEncoding.EncodeToString([]byte(v)), label)
			add(base64.RawStdEncoding.EncodeToString([]byte(v)), label)
			add(base64.URLEncoding.EncodeToString([]byte(v)), label)
			add(url.QueryEscape(v), label)
			add(url.PathEscape(v), label)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return len(out[i].pat) > len(out[j].pat) })
	return out
}

// redactWriter masks secret values in a byte stream. It holds back the last
// maxLen-1 bytes so a value split across writes is still caught, and releases
// them on Flush.
type redactWriter struct {
	w       io.Writer
	needles []needle
	maxLen  int
	buf     []byte
}

func newRedactWriter(w io.Writer, needles []needle) *redactWriter {
	m := 0
	for _, n := range needles {
		if len(n.pat) > m {
			m = len(n.pat)
		}
	}
	return &redactWriter{w: w, needles: needles, maxLen: m}
}

type span struct {
	start, end int
	label      string
}

// spans finds all non-overlapping matches in b, preferring earlier and longer ones.
func (r *redactWriter) spans(b []byte) []span {
	var all []span
	for _, n := range r.needles {
		off := 0
		for {
			i := bytes.Index(b[off:], n.pat)
			if i < 0 {
				break
			}
			all = append(all, span{off + i, off + i + len(n.pat), n.label})
			off += i + 1
		}
	}
	sort.SliceStable(all, func(i, j int) bool {
		if all[i].start != all[j].start {
			return all[i].start < all[j].start
		}
		return all[i].end-all[i].start > all[j].end-all[j].start
	})
	var out []span
	last := 0
	for _, s := range all {
		if s.start >= last {
			out = append(out, s)
			last = s.end
		}
	}
	return out
}

func (r *redactWriter) emit(b []byte, upto int, spans []span) error {
	pos := 0
	var o bytes.Buffer
	for _, s := range spans {
		if s.end > upto {
			break
		}
		o.Write(b[pos:s.start])
		o.WriteString(s.label)
		pos = s.end
	}
	o.Write(b[pos:upto])
	_, err := r.w.Write(o.Bytes())
	return err
}

func (r *redactWriter) Write(p []byte) (int, error) {
	if r.maxLen == 0 {
		return r.w.Write(p)
	}
	r.buf = append(r.buf, p...)
	spans := r.spans(r.buf)
	cut := len(r.buf) - (r.maxLen - 1)
	if cut < 0 {
		cut = 0
	}
	for _, s := range spans {
		if s.start < cut && s.end > cut {
			cut = s.end
		}
	}
	if cut > 0 {
		if err := r.emit(r.buf, cut, spans); err != nil {
			return 0, err
		}
		r.buf = append(r.buf[:0], r.buf[cut:]...)
	}
	return len(p), nil
}

// Flush writes whatever is still held back.
func (r *redactWriter) Flush() error {
	if len(r.buf) == 0 {
		return nil
	}
	spans := r.spans(r.buf)
	err := r.emit(r.buf, len(r.buf), spans)
	r.buf = nil
	return err
}
