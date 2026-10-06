package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"gbm.dev/emltools/internal/arc"
	"gbm.dev/emltools/internal/dkimcore"
	"gbm.dev/emltools/internal/mailmsg"
)

const base = "From: Joe SixPack <joe@football.example.com>\r\n" +
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

// signFixture returns the fixture with a DKIM-Signature prepended.
func signFixture(t *testing.T, key ed25519.PrivateKey) string {
	t.Helper()
	hdr, err := dkimcore.Sign(mustMsg(t, base), key, dkimcore.SignOptions{
		Domain: "football.example.com", Selector: "mta",
		HeaderCanon: "relaxed", BodyCanon: "relaxed",
		T: time.Unix(1057982437, 0),
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(hdr) + "\r\n" + base
}

func TestRedkimRecoverAfterTamper(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	signed := signFixture(t, priv)

	// tamper the body and shift the Date header
	tampered := strings.Replace(signed, "hungry", "HUNGRY", 1)
	tampered = strings.Replace(tampered,
		"Date: Fri, 11 Jul 2003 21:00:37 -0700 (PDT)",
		"Date: Sun, 14 Sep 2026 23:05:39 +0000", 1)

	// the old signature must no longer verify
	old := mustMsg(t, tampered)
	sigs := old.GetAll("DKIM-Signature")
	if len(sigs) != 1 {
		t.Fatalf("want 1 stale signature, got %d", len(sigs))
	}
	stale, _ := dkimcore.ParseSig("DKIM-Signature", sigs[0].Raw)
	if res := stale.Verify(old, dkimcore.StaticKeyLookup(pub)); res.Valid {
		t.Fatal("stale signature still verifies; tamper setup is broken")
	}

	out, err := redkim([]byte(tampered), priv, Options{
		Domain: "football.example.com", Selector: "redkim",
		HeaderCanon: "relaxed", BodyCanon: "relaxed",
	})
	if err != nil {
		t.Fatal(err)
	}

	// output must be CRLF-normalized
	if n, rn := bytes.Count(out, []byte("\n")), bytes.Count(out, []byte("\r\n")); n != rn {
		t.Fatalf("output has %d bare LF among %d newlines", n-rn, n)
	}

	m := mustMsg(t, string(out))
	if got := m.GetAll("DKIM-Signature"); len(got) != 1 {
		t.Fatalf("want exactly 1 DKIM-Signature, got %d", len(got))
	}
	for _, name := range []string{"ARC-Authentication-Results", "ARC-Message-Signature", "ARC-Seal"} {
		if len(m.GetAll(name)) != 0 {
			t.Fatalf("output still has %s", name)
		}
	}
	sig, _ := dkimcore.ParseSig("DKIM-Signature", m.Headers[0].Raw)
	res := sig.Verify(m, dkimcore.StaticKeyLookup(pub))
	if !res.Valid || !res.BHValid {
		t.Fatalf("redkim signature does not verify: %v", res.Errs)
	}

	// t= defaults to the Date header epoch
	if ts, _ := sig.Timestamp(); ts.Unix() != m.Date().Unix() {
		t.Fatalf("t= = %d, want Date epoch %d", ts.Unix(), m.Date().Unix())
	}
}

func TestRedkimExplicitTimestampWins(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signed := signFixture(t, priv)
	out, err := redkim([]byte(signed), priv, Options{
		Domain: "football.example.com", Selector: "redkim",
		HeaderCanon: "relaxed", BodyCanon: "relaxed",
		T: time.Unix(1117574999, 0),
	})
	if err != nil {
		t.Fatal(err)
	}
	m := mustMsg(t, string(out))
	sig, _ := dkimcore.ParseSig("DKIM-Signature", m.Headers[0].Raw)
	if ts, _ := sig.Timestamp(); ts.Unix() != 1117574999 {
		t.Fatalf("t= = %v, want 1117574999", ts.Unix())
	}
}

func TestRedkimFreshARCSeal(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	signed := signFixture(t, priv)
	tampered := strings.Replace(signed, "hungry", "HUNGRY", 1)

	out, err := redkim([]byte(tampered), priv, Options{
		Domain: "forwarder.example", Selector: "arc1",
		HeaderCanon: "relaxed", BodyCanon: "relaxed",
		ARC:         true,
		AuthResults: "dkim=pass header.d=football.example.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	m := mustMsg(t, string(out))
	for _, name := range staleHeaders {
		if len(m.GetAll(name)) != 1 {
			t.Fatalf("want exactly one %s, got %d", name, len(m.GetAll(name)))
		}
	}
	res := arc.Validate(m, dkimcore.StaticKeyLookup(pub))
	if res.Status != "pass" {
		t.Fatalf("arc status = %s, errs=%v", res.Status, res.Errs)
	}
	if len(res.Sets) != 1 || res.Sets[0].I != 1 {
		t.Fatalf("sets = %+v, want a single i=1 set", res.Sets)
	}
	if !res.AMS[0].Valid {
		t.Fatalf("AMS invalid: %v", res.AMS[0].Errs)
	}
}

func TestStripStale(t *testing.T) {
	raw := "DKIM-Signature: v=1; d=old1;\r\n" +
		"ARC-Authentication-Results: i=1; dkim=pass\r\n" +
		"From: a@b.example\r\n" +
		"dkim-signature: v=1; d=old2;\r\n" +
		"ARC-Message-Signature: a=rsa-sha256; b=x\r\n" +
		"Subject: keep me\r\n" +
		"ARC-Seal: a=ed25519-sha256; b=y\r\n" +
		"DKIM-SIGNATURE: v=1; d=old3;\r\n" +
		"\r\n" +
		"body\r\n"
	msg := mustMsg(t, raw)
	out := string(stripStale(msg)) + "\r\n" + string(msg.RawBody)
	m := mustMsg(t, out)
	for _, name := range staleHeaders {
		if len(m.GetAll(name)) != 0 {
			t.Fatalf("%s survived stripping", name)
		}
	}
	if m.Get("From") != "a@b.example" || m.Get("Subject") != "keep me" {
		t.Fatalf("kept headers damaged: %+v", m.Headers)
	}
}
