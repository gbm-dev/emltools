package dkimcanon

import (
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"testing"
)

// Vectors from RFC 6376 §3.4.5 examples 1-3.
func TestHeaderCanonRFC6376(t *testing.T) {
	if got := HeaderRelaxed("A", " X"); string(got) != "a:X\r\n" {
		t.Errorf("HeaderRelaxed(A) = %q, want %q", got, "a:X\r\n")
	}
	// "B <SP> : <SP> Y <HTAB><CRLF><HTAB> Z <SP><SP>"
	if got := HeaderRelaxed("B", "Y\t\r\n\t Z  "); string(got) != "b:Y Z\r\n" {
		t.Errorf("HeaderRelaxed(B) = %q, want %q", got, "b:Y Z\r\n")
	}
	raw := []byte("B <SP> : <SP> Y <HTAB>\r\n<HTAB> Z <SP><SP>")
	want := append(append([]byte{}, raw...), '\r', '\n')
	if got := HeaderSimple(raw); string(got) != string(want) {
		t.Errorf("HeaderSimple = %q, want %q", got, want)
	}
}

func TestBodyCanonRFC6376(t *testing.T) {
	in := []byte(" C \r\nD \t E\r\n\r\n\r\n")
	if got := BodySimple(in); string(got) != " C \r\nD \t E\r\n" {
		t.Errorf("BodySimple = %q", got)
	}
	if got := BodyRelaxed(in); string(got) != " C\r\nD E\r\n" {
		t.Errorf("BodyRelaxed = %q", got)
	}
}

// Hash vectors from RFC 6376 §3.4.3 and §3.4.4.
func TestEmptyBodyHashVectors(t *testing.T) {
	cases := []struct {
		name           string
		body           []byte
		canon          func([]byte) []byte
		want1, want256 string
	}{
		{"simple-empty", []byte(""), BodySimple,
			"uoq1oCgLlTqpdDX/iUbLy7J1Wic=",
			"frcCV1k9oG9oKj3dpUqdJg1PxRT2RSN/XKdLCPjaYaY="},
		{"relaxed-empty", []byte(""), BodyRelaxed,
			"2jmj7l5rSw0yVb/vlWAYkK/YBwk=",
			"47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := b64(sha1.Sum(c.canon(c.body))); got != c.want1 {
				t.Errorf("sha1 = %s, want %s", got, c.want1)
			}
			s := sha256.Sum256(c.canon(c.body))
			if got := base64.StdEncoding.EncodeToString(s[:]); got != c.want256 {
				t.Errorf("sha256 = %s, want %s", got, c.want256)
			}
		})
	}
}

func b64(b [20]byte) string { return base64.StdEncoding.EncodeToString(b[:]) }

func TestBodyCanonEdgeCases(t *testing.T) {
	if got := BodySimple(nil); string(got) != "\r\n" {
		t.Errorf("BodySimple(empty) = %q", got)
	}
	if got := BodyRelaxed(nil); len(got) != 0 {
		t.Errorf("BodyRelaxed(empty) = %q", got)
	}
	if got := BodySimple([]byte("a")); string(got) != "a\r\n" {
		t.Errorf("BodySimple(no crlf) = %q", got)
	}
	if got := BodyRelaxed([]byte("a")); string(got) != "a\r\n" {
		t.Errorf("BodyRelaxed(no crlf) = %q, want CRLF added", got)
	}
}

func TestParseCanon(t *testing.T) {
	cases := []struct{ in, h, b string }{
		{"", "simple", "simple"},
		{"Relaxed", "relaxed", "simple"},
		{"relaxed/relaxed", "relaxed", "relaxed"},
		{"simple/simple", "simple", "simple"},
		{"relaxed/SIMPLE", "relaxed", "simple"},
	}
	for _, c := range cases {
		h, b := ParseCanon(c.in)
		if fmt.Sprint(h, b) != fmt.Sprint(c.h, c.b) {
			t.Errorf("ParseCanon(%q) = %s/%s, want %s/%s", c.in, h, b, c.h, c.b)
		}
	}
}
