package dkimcore

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"gbm.dev/emltools/internal/mailmsg"
)

const fixture = "From: Joe SixPack <joe@football.example.com>\r\n" +
	"To: Suzie Q <suzie@shopping.example.net>\r\n" +
	"Subject: Is dinner ready?\r\n" +
	"Date: Fri, 11 Jul 2003 21:00:37 -0700 (PDT)\r\n" +
	"Message-ID: <20030712040037.46341.5F8J@football.example.com>\r\n" +
	"\r\n" +
	"Hi.\r\n\r\nWe lost the game. Are you hungry yet?\r\n\r\nJoe.\r\n"

func mustMsg(t *testing.T, raw string) *mailmsg.Message {
	t.Helper()
	m, err := mailmsg.Parse([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestSignVerifyRSARelaxed(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 1024)
	msg := mustMsg(t, fixture)
	hdr, err := Sign(msg, key, SignOptions{
		Domain: "football.example.com", Selector: "test",
		HeaderCanon: "relaxed", BodyCanon: "relaxed",
		T: time.Unix(1117574938, 0).UTC(), X: time.Unix(1118006938, 0).UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}
	signed := mustMsg(t, string(hdr)+"\r\n"+fixture)
	sig, err := ParseSig("DKIM-Signature", signed.Headers[0].Raw)
	if err != nil {
		t.Fatal(err)
	}
	res := sig.Verify(signed, StaticKeyLookup(&key.PublicKey))
	if !res.Valid || !res.BHValid {
		t.Fatalf("verify failed: %+v errs=%v", res, res.Errs)
	}
	if res.Domain != "football.example.com" || res.Selector != "test" {
		t.Fatalf("bad identity: %+v", res)
	}
	if res.T == nil || res.T.Unix() != 1117574938 || res.X == nil || res.X.Unix() != 1118006938 {
		t.Fatalf("t=/x= not round-tripped: %+v", res)
	}
}

func TestSignVerifyRSASimple(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 1024)
	msg := mustMsg(t, fixture)
	hdr, err := Sign(msg, key, SignOptions{Domain: "example.com", Selector: "s1"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(hdr), "c=simple/simple") {
		t.Fatalf("default canon not simple/simple: %q", hdr)
	}
	signed := mustMsg(t, string(hdr)+"\r\n"+fixture)
	sig, _ := ParseSig("DKIM-Signature", signed.Headers[0].Raw)
	res := sig.Verify(signed, StaticKeyLookup(&key.PublicKey))
	if !res.Valid {
		t.Fatalf("simple/simple verify failed: %v", res.Errs)
	}
}

func TestSignVerifyEd25519(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	msg := mustMsg(t, fixture)
	hdr, err := Sign(msg, priv, SignOptions{
		Domain: "example.com", Selector: "ed",
		HeaderCanon: "relaxed", BodyCanon: "relaxed",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(hdr), "a=ed25519-sha256") {
		t.Fatalf("algo not inferred: %q", hdr)
	}
	signed := mustMsg(t, string(hdr)+"\r\n"+fixture)
	sig, _ := ParseSig("DKIM-Signature", signed.Headers[0].Raw)
	res := sig.Verify(signed, StaticKeyLookup(pub))
	if !res.Valid || !res.BHValid {
		t.Fatalf("ed25519 verify failed: %v", res.Errs)
	}
}

func TestTamperBody(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 1024)
	msg := mustMsg(t, fixture)
	hdr, _ := Sign(msg, key, SignOptions{
		Domain: "example.com", Selector: "s", HeaderCanon: "relaxed", BodyCanon: "relaxed",
	})
	tampered := mustMsg(t, string(hdr)+"\r\n"+strings.Replace(fixture, "hungry", "HUNGRY", 1))
	sig, _ := ParseSig("DKIM-Signature", tampered.Headers[0].Raw)
	res := sig.Verify(tampered, StaticKeyLookup(&key.PublicKey))
	if res.BHValid || res.Valid {
		t.Fatalf("tampered body verified: %+v", res)
	}
}

func TestTamperHeader(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 1024)
	msg := mustMsg(t, fixture)
	hdr, _ := Sign(msg, key, SignOptions{
		Domain: "example.com", Selector: "s", HeaderCanon: "relaxed", BodyCanon: "relaxed",
	})
	bad := strings.Replace(fixture, "Is dinner ready?", "Is dinner ready? NOW", 1)
	tampered := mustMsg(t, string(hdr)+"\r\n"+bad)
	sig, _ := ParseSig("DKIM-Signature", tampered.Headers[0].Raw)
	res := sig.Verify(tampered, StaticKeyLookup(&key.PublicKey))
	if res.Valid {
		t.Fatalf("tampered header verified")
	}
	if !res.BHValid {
		t.Fatalf("subject change should not affect body hash")
	}
}

func TestRepeatedHeaderBottomUp(t *testing.T) {
	// h=from:from (oversigning): both From headers are covered
	key, _ := rsa.GenerateKey(rand.Reader, 1024)
	two := strings.Replace(fixture,
		"From: Joe SixPack <joe@football.example.com>\r\n",
		"From: backup@football.example.com\r\nFrom: Joe SixPack <joe@football.example.com>\r\n", 1)
	msg := mustMsg(t, two)
	hdr, _ := Sign(msg, key, SignOptions{
		Domain: "example.com", Selector: "s",
		HeaderCanon: "relaxed", BodyCanon: "relaxed",
		HeaderList: []string{"from", "from", "to", "subject", "date", "message-id"},
	})
	signed := mustMsg(t, string(hdr)+"\r\n"+two)
	sig, _ := ParseSig("DKIM-Signature", signed.Headers[0].Raw)
	res := sig.Verify(signed, StaticKeyLookup(&key.PublicKey))
	if !res.Valid {
		t.Fatalf("oversigned verify failed: %v", res.Errs)
	}
	// dropping the top From header must break the signature
	removed := strings.Replace(two, "From: backup@football.example.com\r\n", "", 1)
	altered := mustMsg(t, string(hdr)+"\r\n"+removed)
	sig2, _ := ParseSig("DKIM-Signature", altered.Headers[0].Raw)
	if res2 := sig2.Verify(altered, StaticKeyLookup(&key.PublicKey)); res2.Valid {
		t.Fatal("signature survived header removal despite oversigning")
	}
}

func TestKeyFromTXT(t *testing.T) {
	// RFC-style record: quoted, split across strings
	rec := "\"v=DKIM1; k=rsa; \" \"p=MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAKj=\""
	_, _, err := KeyFromTXT(rec)
	if err == nil {
		t.Fatal("garbage p= should fail to parse")
	}
	revoked := "v=DKIM1; k=rsa; p="
	_, _, err = KeyFromTXT(revoked)
	if err == nil || !strings.Contains(err.Error(), "revoked") {
		t.Fatalf("revoked key error = %v", err)
	}
	badVersion := "v=DKIM2; p=AAAA"
	_, _, err = KeyFromTXT(badVersion)
	if err == nil || !strings.Contains(err.Error(), "version") {
		t.Fatalf("version error = %v", err)
	}

	// RFC 8463 §3: k=ed25519 carries the raw 32-byte public key
	raw := make([]byte, ed25519.PublicKeySize)
	for i := range raw {
		raw[i] = byte(i)
	}
	edRec := "v=DKIM1; k=ed25519; p=" + base64.StdEncoding.EncodeToString(raw)
	got, k, err := KeyFromTXT(edRec)
	if err != nil {
		t.Fatal(err)
	}
	edPub, ok := got.(ed25519.PublicKey)
	if !ok || k != "ed25519" || !bytes.Equal(edPub, raw) {
		t.Fatalf("ed25519 record = %T k=%s %v", got, k, got)
	}
	if _, _, err := KeyFromTXT("v=DKIM1; k=ed25519; p=AAAA"); err == nil {
		t.Fatal("short ed25519 p= should fail")
	}
}

func TestParseSigFolding(t *testing.T) {
	raw := []byte("DKIM-Signature: v=1; a=rsa-sha256;\r\n\td=example.com; s=s1;\r\n\th=from:to;\r\n\tt=1117574938;")
	sig, err := ParseSig("DKIM-Signature", raw)
	if err != nil {
		t.Fatal(err)
	}
	if sig.Tag("d") != "example.com" || sig.Tag("s") != "s1" {
		t.Fatalf("tags = %v", sig.Tags)
	}
	if ts, ok := sig.Timestamp(); !ok || ts.Unix() != 1117574938 {
		t.Fatalf("t= = %v", ts)
	}
	// b= blanking must not eat bh=
	sig.Tags["bh"] = "QUJD"
	sig.Tags["b"] = "REVG"
	if got := string(reBTag.ReplaceAll([]byte("bh=QUJD; b=REVG"), []byte("b="))); got != "bh=QUJD; b=" {
		t.Fatalf("b= blanking broke bh=: %q", got)
	}
}

func TestVerifyMissingTags(t *testing.T) {
	sig, _ := ParseSig("DKIM-Signature", []byte("DKIM-Signature: v=1; a=rsa-sha256;"))
	res := sig.Verify(mustMsg(t, fixture), nil)
	if res.Valid || len(res.Errs) == 0 {
		t.Fatalf("missing tags must fail: %+v", res)
	}
}
