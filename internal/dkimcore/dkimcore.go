// Package dkimcore implements DKIM signing and verification (RFC 6376) and
// the message-signature mechanics reused by ARC (RFC 8617).
package dkimcore

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	"gbm.dev/emltools/internal/dkimcanon"
	"gbm.dev/emltools/internal/mailmsg"
)

// Sig is a parsed DKIM-Signature, ARC-Message-Signature, or ARC-Seal header.
type Sig struct {
	HeaderName string // "DKIM-Signature", "ARC-Message-Signature", "ARC-Seal"
	Raw        []byte // CRLF-normalized header text, no trailing CRLF
	Tags       map[string]string
	Order      []string // tags in order of first appearance
}

var (
	// name:value split on the first colon (FWS tolerated around the name)
	reHdrName = regexp.MustCompile(`^([^:\s]+)\s*:\s?`)
	reBTag    = regexp.MustCompile(`(?i)\bb=[^;]*`)
)

// BlankB returns the header text with the b= tag value removed. ARC seals and
// DKIM hash inputs use the blanked form.
func BlankB(raw []byte) []byte {
	return reBTag.ReplaceAll(raw, []byte("b="))
}

// ParseSig builds a Sig from a raw header (name line plus folds, no trailing CRLF).
func ParseSig(headerName string, raw []byte) (*Sig, error) {
	s := &Sig{HeaderName: headerName, Raw: append([]byte{}, raw...), Tags: map[string]string{}}
	text := string(raw)
	m := reHdrName.FindStringSubmatch(text)
	if m == nil {
		return nil, fmt.Errorf("%s: cannot split name from value", headerName)
	}
	text = text[len(m[0]):]
	for _, kv := range strings.Split(text, ";") {
		kv = strings.TrimSpace(kv)
		if kv == "" {
			continue
		}
		k, v, found := strings.Cut(kv, "=")
		if !found {
			return nil, fmt.Errorf("%s: malformed tag %q", headerName, kv)
		}
		key := strings.ToLower(strings.TrimSpace(k))
		if _, dup := s.Tags[key]; !dup {
			s.Order = append(s.Order, key)
		}
		s.Tags[key] = strings.TrimSpace(v)
	}
	return s, nil
}

// Tag returns a tag value with interior FWS removed.
func (s *Sig) Tag(k string) string { return stripWS(s.Tags[k]) }

// Instance parses the i= tag (ARC), defaulting to 0.
func (s *Sig) Instance() int {
	n, _ := strconv.Atoi(strings.TrimSpace(s.Tags["i"]))
	return n
}

// Timestamp parses the t= tag.
func (s *Sig) Timestamp() (time.Time, bool) {
	if n, err := strconv.ParseInt(stripWS(s.Tags["t"]), 10, 64); err == nil {
		return time.Unix(n, 0).UTC(), true
	}
	return time.Time{}, false
}

// Expiry parses the x= tag.
func (s *Sig) Expiry() (time.Time, bool) {
	if n, err := strconv.ParseInt(stripWS(s.Tags["x"]), 10, 64); err == nil {
		return time.Unix(n, 0).UTC(), true
	}
	return time.Time{}, false
}

func stripWS(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch r {
		case ' ', '\t', '\r', '\n':
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// VerifyResult carries the outcome of one signature check.
type VerifyResult struct {
	Domain    string
	Selector  string
	Identity  string
	Algo      string
	Canon     string
	T, X      *time.Time
	BHValid   bool // body hash matched
	Valid     bool // full signature verified
	KeySource string
	Errs      []string
}

func (r *VerifyResult) fail(format string, args ...any) {
	r.Errs = append(r.Errs, fmt.Sprintf(format, args...))
}

// KeyLookup resolves the public key for a (selector, domain) pair, returning
// the key, a human-readable source description, and any error.
type KeyLookup func(selector, domain string) (crypto.PublicKey, string, error)

// DNSKeyLookup queries DNS TXT at <selector>._domainkey.<domain>.
func DNSKeyLookup(resolver *net.Resolver) KeyLookup {
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	return func(selector, domain string) (crypto.PublicKey, string, error) {
		txts, err := resolver.LookupTXT(context.Background(), selector+"._domainkey."+domain)
		if err != nil {
			return nil, "", fmt.Errorf("dns: %w", err)
		}
		rec := stripWS(strings.Join(txts, ""))
		pub, _, err := KeyFromTXT(rec)
		return pub, "dns:" + selector + "._domainkey." + domain, err
	}
}

// StaticKeyLookup always returns the given key (offline fixtures).
func StaticKeyLookup(pub crypto.PublicKey) KeyLookup {
	return func(selector, domain string) (crypto.PublicKey, string, error) {
		return pub, "pem", nil
	}
}

// KeyFromTXT parses a DKIM key record (v=DKIM1; k=rsa; p=...).
func KeyFromTXT(rec string) (crypto.PublicKey, string, error) {
	rec = strings.ReplaceAll(rec, `"`, "")
	tags := map[string]string{}
	for _, kv := range strings.Split(rec, ";") {
		if k, v, ok := strings.Cut(kv, "="); ok {
			tags[strings.ToLower(strings.TrimSpace(k))] = strings.TrimSpace(v)
		}
	}
	if v, ok := tags["v"]; ok && v != "DKIM1" {
		return nil, "", fmt.Errorf("unsupported key record version %q", v)
	}
	p := stripWS(tags["p"])
	if p == "" {
		return nil, "", errors.New("key record has no p= tag (revoked)")
	}
	der, err := base64.StdEncoding.DecodeString(p)
	if err != nil {
		return nil, "", fmt.Errorf("p= base64: %w", err)
	}
	// RFC 8463 §3: k=ed25519 records carry the raw 32-byte public key.
	if tags["k"] == "ed25519" {
		if len(der) != ed25519.PublicKeySize {
			return nil, "", fmt.Errorf("ed25519 p= is %d bytes, want %d", len(der), ed25519.PublicKeySize)
		}
		return ed25519.PublicKey(der), "ed25519", nil
	}
	if pub, err := x509.ParsePKIXPublicKey(der); err == nil {
		return pub, tags["k"], nil
	}
	if pub, err := x509.ParsePKCS1PublicKey(der); err == nil {
		return pub, tags["k"], nil
	}
	return nil, "", errors.New("p= tag is not a PKIX/PKCS#1 public key")
}

// PublicKeyFromPEM parses a PEM public key (PKIX or PKCS#1).
func PublicKeyFromPEM(data []byte) (crypto.PublicKey, error) {
	blk, _ := pem.Decode(data)
	if blk == nil {
		return nil, errors.New("no PEM block found")
	}
	if pub, err := x509.ParsePKIXPublicKey(blk.Bytes); err == nil {
		return pub, nil
	}
	if pub, err := x509.ParsePKCS1PublicKey(blk.Bytes); err == nil {
		return pub, nil
	}
	return nil, errors.New("unsupported PEM public key type")
}

// PrivateKeyFromPEM parses a PEM private key (PKCS#8 or PKCS#1).
func PrivateKeyFromPEM(data []byte) (crypto.Signer, error) {
	blk, _ := pem.Decode(data)
	if blk == nil {
		return nil, errors.New("no PEM block found")
	}
	if key, err := x509.ParsePKCS8PrivateKey(blk.Bytes); err == nil {
		s, ok := key.(crypto.Signer)
		if !ok {
			return nil, errors.New("PKCS#8 key is not a signer")
		}
		return s, nil
	}
	if key, err := x509.ParsePKCS1PrivateKey(blk.Bytes); err == nil {
		return key, nil
	}
	return nil, errors.New("unsupported private key PEM")
}

func hashFunc(algo string) (crypto.Hash, error) {
	switch strings.ToLower(algo) {
	case "rsa-sha256", "ed25519-sha256":
		return crypto.SHA256, nil
	case "rsa-sha1":
		return crypto.SHA1, nil
	}
	return 0, fmt.Errorf("unsupported algorithm %q", algo)
}

func hashBytes(h crypto.Hash, data []byte) []byte {
	if h == crypto.SHA1 {
		s := sha1.Sum(data)
		return s[:]
	}
	s := sha256.Sum256(data)
	return s[:]
}

// Verify checks one signature against the message.
func (s *Sig) Verify(msg *mailmsg.Message, lookup KeyLookup) *VerifyResult {
	r := &VerifyResult{
		Domain:   s.Tag("d"),
		Selector: s.Tag("s"),
		Identity: s.Tag("i"),
		Algo:     strings.ToLower(s.Tags["a"]),
		Canon:    strings.ToLower(s.Tags["c"]),
	}
	if t, ok := s.Timestamp(); ok {
		r.T = &t
	}
	if x, ok := s.Expiry(); ok {
		r.X = &x
	}

	switch {
	case r.Domain == "":
		r.fail("missing d= tag")
		return r
	case r.Selector == "":
		r.fail("missing s= tag")
		return r
	case s.Tags["b"] == "":
		r.fail("missing b= tag")
		return r
	case s.Tags["bh"] == "":
		r.fail("missing bh= tag")
		return r
	case r.Algo == "":
		r.fail("missing a= tag")
		return r
	}
	if !containsToken(strings.ToLower(s.Tag("h")), "from") {
		r.fail("h= does not cover From (RFC 6376 §5.4)")
	}

	hf, err := hashFunc(r.Algo)
	if err != nil {
		r.fail("%v", err)
		return r
	}
	hCanon, bCanon := dkimcanon.ParseCanon(s.Tags["c"])

	// body hash
	body := dkimcanon.BodySimple(msg.RawBody)
	if bCanon == "relaxed" {
		body = dkimcanon.BodyRelaxed(msg.RawBody)
	}
	if l := s.Tags["l"]; l != "" {
		n, err := strconv.Atoi(stripWS(l))
		if err != nil || n < 0 || n > len(body) {
			r.fail("invalid l= tag %q", l)
		} else {
			body = body[:n]
		}
	}
	wantBH, err := base64.StdEncoding.DecodeString(stripWS(s.Tags["bh"]))
	if err != nil {
		r.fail("bh= base64: %v", err)
		return r
	}
	gotBH := hashBytes(hf, body)
	r.BHValid = bytes.Equal(gotBH, wantBH)
	if !r.BHValid {
		r.fail("body hash mismatch (computed %s)", base64.StdEncoding.EncodeToString(gotBH))
	}

	// header hash
	data, err := s.hashInput(msg, hCanon)
	if err != nil {
		r.fail("%v", err)
		return r
	}

	if lookup == nil {
		lookup = DNSKeyLookup(nil)
	}
	pub, src, err := lookup(r.Selector, r.Domain)
	if err != nil {
		r.KeySource = "unavailable"
		r.fail("key lookup: %v", err)
		return r
	}
	r.KeySource = src

	sig, err := base64.StdEncoding.DecodeString(stripWS(s.Tags["b"]))
	if err != nil {
		r.fail("b= base64: %v", err)
		return r
	}
	switch key := pub.(type) {
	case *rsa.PublicKey:
		if !strings.HasPrefix(r.Algo, "rsa-") {
			r.fail("algorithm %s does not match RSA key", r.Algo)
			return r
		}
		if err := rsa.VerifyPKCS1v15(key, hf, hashBytes(hf, data), sig); err != nil {
			r.fail("RSA verification failed: %v", err)
			return r
		}
	case ed25519.PublicKey:
		if r.Algo != "ed25519-sha256" {
			r.fail("algorithm %s does not match Ed25519 key", r.Algo)
			return r
		}
		// RFC 8463 §4: Ed25519 signs the SHA-256 message hash, not the raw input.
		if !ed25519.Verify(key, hashBytes(hf, data), sig) {
			r.fail("Ed25519 verification failed")
			return r
		}
	default:
		r.fail("unsupported key type %T", pub)
		return r
	}
	// RFC 6376 §6.1: the signature is only valid if bh= also matched.
	if !r.BHValid {
		return r
	}
	r.Valid = true
	return r
}

// hashInput builds the header-hash input: headers selected from h= (from the
// bottom up per name, per RFC 6376 §5.4.2), then the signature header itself
// with b= blanked and no trailing CRLF.
func (s *Sig) hashInput(msg *mailmsg.Message, hCanon string) ([]byte, error) {
	var buf bytes.Buffer
	used := map[string]int{}
	for _, name := range strings.Split(strings.ToLower(s.Tag("h")), ":") {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		hdr := selectBottomUp(msg, name, used)
		if hdr == nil {
			continue
		}
		if hCanon == "relaxed" {
			_, val := splitHeader(hdr.Raw) // value only; Raw includes "Name:"
			buf.Write(dkimcanon.HeaderRelaxed(hdr.Name, dkimcanon.Unfold(string(val))))
		} else {
			buf.Write(dkimcanon.HeaderSimple(hdr.Raw))
		}
	}
	sigHeader := reBTag.ReplaceAll(s.Raw, []byte("b="))
	if hCanon == "relaxed" {
		name, value := splitHeader(sigHeader)
		// RFC 6376 §3.7: the final (blanked) signature header carries no
		// trailing CRLF; HeaderRelaxed always appends one.
		buf.Write(bytes.TrimSuffix(dkimcanon.HeaderRelaxed(name, string(value)), []byte("\r\n")))
	} else {
		buf.Write(sigHeader) // simple: exact bytes, no trailing CRLF
	}
	return buf.Bytes(), nil
}

// selectBottomUp returns the n-th instance of name counted from the last
// header, where n is how many times the name was already consumed.
func selectBottomUp(msg *mailmsg.Message, name string, used map[string]int) *mailmsg.Header {
	var matches []*mailmsg.Header
	for i := range msg.Headers {
		if strings.EqualFold(msg.Headers[i].Name, name) {
			matches = append(matches, &msg.Headers[i])
		}
	}
	n := used[name]
	if n >= len(matches) {
		return nil
	}
	used[name]++
	return matches[len(matches)-1-n]
}

func splitHeader(raw []byte) (string, []byte) {
	m := reHdrName.FindSubmatchIndex(raw)
	if m == nil {
		return "", raw
	}
	return string(raw[m[2]:m[3]]), raw[m[1]:]
}

func containsToken(list, tok string) bool {
	for _, t := range strings.Split(list, ":") {
		if strings.TrimSpace(t) == tok {
			return true
		}
	}
	return false
}

// VerifyDetached checks a signature over an arbitrary byte string (used by
// ARC seals, which sign headers only and carry no bh=).
func VerifyDetached(algo string, data, sig []byte, pub crypto.PublicKey) error {
	hf, err := hashFunc(algo)
	if err != nil {
		return err
	}
	switch key := pub.(type) {
	case *rsa.PublicKey:
		return rsa.VerifyPKCS1v15(key, hf, hashBytes(hf, data), sig)
	case ed25519.PublicKey:
		if algo != "ed25519-sha256" {
			return fmt.Errorf("algorithm %s does not match Ed25519 key", algo)
		}
		if !ed25519.Verify(key, hashBytes(hf, data), sig) {
			return errors.New("Ed25519 verification failed")
		}
		return nil
	default:
		return fmt.Errorf("unsupported key type %T", pub)
	}
}

// SignDetached signs an arbitrary byte string (ARC seal generation).
func SignDetached(algo string, data []byte, key crypto.Signer) ([]byte, error) {
	hf, err := hashFunc(algo)
	if err != nil {
		return nil, err
	}
	switch k := key.(type) {
	case *rsa.PrivateKey:
		return rsa.SignPKCS1v15(rand.Reader, k, hf, hashBytes(hf, data))
	case ed25519.PrivateKey:
		return ed25519.Sign(k, hashBytes(hf, data)), nil // RFC 8463 §4: over the digest
	default:
		return nil, fmt.Errorf("unsupported signer type %T", key)
	}
}

// ---------- signing ----------

// SignOptions configures Sign.
type SignOptions struct {
	HeaderName       string // default "DKIM-Signature" (use "ARC-Message-Signature" for ARC)
	Domain, Selector string
	Algo             string   // rsa-sha256 | ed25519-sha256 (default: inferred from key)
	HeaderCanon      string   // simple (default) | relaxed
	BodyCanon        string   // simple (default) | relaxed
	HeaderList       []string // h= names; default covers the big five
	T, X             time.Time
	Instance         int      // ARC instance (i=); 0 = omit
	Identity         string   // i= (optional, DKIM AUID)
	Length           int      // l= octets (0 = omit)
	ExtraTags        []string // appended verbatim, e.g. "i=@example.com"
}

// Sign produces a folded DKIM-Signature header (no trailing CRLF), ready to
// prepend to the message header block.
func Sign(msg *mailmsg.Message, key crypto.Signer, o SignOptions) ([]byte, error) {
	if o.HeaderCanon == "" {
		o.HeaderCanon = "simple"
	}
	if o.BodyCanon == "" {
		o.BodyCanon = "simple"
	}
	if len(o.HeaderList) == 0 {
		o.HeaderList = []string{"from", "to", "subject", "date", "message-id"}
	}
	if o.Algo == "" {
		switch key.(type) {
		case ed25519.PrivateKey:
			o.Algo = "ed25519-sha256"
		case *rsa.PrivateKey:
			o.Algo = "rsa-sha256"
		default:
			return nil, fmt.Errorf("unsupported signer type %T", key)
		}
	}
	hf, err := hashFunc(o.Algo)
	if err != nil {
		return nil, err
	}

	body := dkimcanon.BodySimple(msg.RawBody)
	if o.BodyCanon == "relaxed" {
		body = dkimcanon.BodyRelaxed(msg.RawBody)
	}
	if o.Length > 0 {
		if o.Length > len(body) {
			return nil, fmt.Errorf("l=%d exceeds canonicalized body of %d octets", o.Length, len(body))
		}
		body = body[:o.Length]
	}
	bh := base64.StdEncoding.EncodeToString(hashBytes(hf, body))

	headerName := o.HeaderName
	if headerName == "" {
		headerName = "DKIM-Signature"
	}
	pairs := []string{
		"v=1",
		"a=" + o.Algo,
		"c=" + o.HeaderCanon + "/" + o.BodyCanon,
		"d=" + o.Domain,
		"s=" + o.Selector,
	}
	if !o.T.IsZero() {
		pairs = append(pairs, "t="+strconv.FormatInt(o.T.Unix(), 10))
	}
	if !o.X.IsZero() {
		pairs = append(pairs, "x="+strconv.FormatInt(o.X.Unix(), 10))
	}
	if o.Instance > 0 {
		pairs = append(pairs, "i="+strconv.Itoa(o.Instance))
	}
	if o.Identity != "" {
		pairs = append(pairs, "i="+o.Identity)
	}
	if o.Length > 0 {
		pairs = append(pairs, "l="+strconv.Itoa(o.Length))
	}
	pairs = append(pairs,
		"h="+strings.Join(o.HeaderList, ":"),
		"bh="+bh,
	)
	for _, extra := range o.ExtraTags {
		pairs = append(pairs, extra)
	}

	// Header text with empty b=, hashed exactly as a verifier will see it
	// after blanking b=; then the signature value is appended and folded.
	text := headerName + ": " + strings.Join(pairs, "; ") + "; b="
	placeholder, err := ParseSig(headerName, []byte(text))
	if err != nil {
		return nil, err
	}
	data, err := placeholder.hashInput(msg, o.HeaderCanon)
	if err != nil {
		return nil, err
	}

	var sig []byte
	switch k := key.(type) {
	case *rsa.PrivateKey:
		sig, err = rsa.SignPKCS1v15(rand.Reader, k, hf, hashBytes(hf, data))
	case ed25519.PrivateKey:
		sig = ed25519.Sign(k, hashBytes(hf, data)) // RFC 8463 §4: over the digest
	default:
		return nil, fmt.Errorf("unsupported signer type %T", key)
	}
	if err != nil {
		return nil, err
	}
	return []byte(text + fold64(base64.StdEncoding.EncodeToString(sig))), nil
}

// fold64 wraps long base64 values onto continuation lines.
func fold64(b string) string {
	var out strings.Builder
	for len(b) > 60 {
		out.WriteString(b[:60])
		out.WriteString("\r\n\t")
		b = b[60:]
	}
	out.WriteString(b)
	return out.String()
}
