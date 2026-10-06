// Package dkimcanon implements DKIM canonicalization (RFC 6376 §3.4).
package dkimcanon

import (
	"bytes"
	"regexp"
	"strings"
)

// Unfold removes fold CRLFs, keeping the WSP that followed them.
func Unfold(s string) string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' && i+1 < len(s) && (s[i+1] == ' ' || s[i+1] == '\t') {
			continue // drop the newline, keep the WSP
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

var wspRun = regexp.MustCompile(`[ \t]+`)

// HeaderRelaxed renders one header in relaxed form (RFC 6376 §3.4.2):
// lowercase name, unfolded, WSP runs collapsed, no WSP around the colon.
// value should be the unfolded value (leading WSP after colon tolerated).
func HeaderRelaxed(name, value string) []byte {
	v := wspRun.ReplaceAllString(strings.Trim(Unfold(value), " \t"), " ")
	return []byte(strings.ToLower(name) + ":" + v + "\r\n")
}

// HeaderSimple returns the header exactly as it appears (CRLF terminated).
func HeaderSimple(raw []byte) []byte {
	out := make([]byte, 0, len(raw)+2)
	out = append(out, raw...)
	return append(out, '\r', '\n')
}

// BodySimple canonicalizes per §3.4.3: strip trailing empty lines, ensure a
// single trailing CRLF.
func BodySimple(body []byte) []byte {
	b := bytes.TrimRight(body, "\r\n")
	out := make([]byte, 0, len(b)+2)
	out = append(out, b...)
	return append(out, '\r', '\n')
}

// BodyRelaxed canonicalizes per §3.4.4: strip WSP at line ends, collapse WSP
// runs within lines, remove trailing empty lines, then add a trailing CRLF
// for a non-empty body. An empty body canonicalizes to empty input.
func BodyRelaxed(body []byte) []byte {
	lines := bytes.Split(body, []byte("\r\n"))
	out := make([][]byte, 0, len(lines))
	for _, l := range lines {
		l = bytes.TrimRight(l, " \t")
		var sb bytes.Buffer
		prev := false
		for _, c := range l {
			if c == ' ' || c == '\t' {
				if !prev {
					sb.WriteByte(' ')
				}
				prev = true
			} else {
				sb.WriteByte(c)
				prev = false
			}
		}
		out = append(out, sb.Bytes())
	}
	for len(out) > 0 && len(out[len(out)-1]) == 0 {
		out = out[:len(out)-1]
	}
	if len(out) == 0 {
		return nil
	}
	return append(bytes.Join(out, []byte("\r\n")), '\r', '\n')
}

// ParseCanon splits a c= tag like "relaxed/simple" into header/body algos,
// applying the DKIM defaults.
func ParseCanon(c string) (header, body string) {
	header, body = "simple", "simple"
	if c != "" {
		parts := strings.SplitN(strings.ToLower(strings.TrimSpace(c)), "/", 2)
		header = parts[0]
		if len(parts) == 2 {
			body = parts[1]
		}
	}
	return header, body
}
