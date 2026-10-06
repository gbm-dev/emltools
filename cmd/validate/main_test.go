package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gbm.dev/emltools/internal/arc"
	"gbm.dev/emltools/internal/dkimcore"
	"gbm.dev/emltools/internal/mailmsg"
)

func encodePubPEM(pub ed25519.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
}

const fixture = "From: Joe SixPack <joe@football.example.com>\r\n" +
	"To: Suzie Q <suzie@shopping.example.net>\r\n" +
	"Subject: Is dinner ready?\r\n" +
	"Date: Fri, 11 Jul 2003 21:00:37 -0700 (PDT)\r\n" +
	"Message-ID: <20030712040037.46341.5F8J@football.example.com>\r\n" +
	"\r\n" +
	"Hi.\r\n\r\nWe lost the game. Are you hungry yet?\r\n\r\nJoe.\r\n"

// TestValidateSignedFixture runs the validator end-to-end over a DKIM+ARC
// signed message using an offline key file, expecting PASS.
func TestValidateSignedFixture(t *testing.T) {
	dir := t.TempDir()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	pubPEM, err := encodePubPEM(pub)
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(dir, "pub.pem")
	if err := os.WriteFile(keyPath, pubPEM, 0o644); err != nil {
		t.Fatal(err)
	}

	msg, _ := mailmsg.Parse([]byte(fixture))
	dkimHdr, err := dkimcore.Sign(msg, priv, dkimcore.SignOptions{
		Domain: "football.example.com", Selector: "mta",
		HeaderCanon: "relaxed", BodyCanon: "relaxed",
		T: time.Unix(1057982437, 0), // ≈ the Date header
	})
	if err != nil {
		t.Fatal(err)
	}
	msg, _ = mailmsg.Parse([]byte(string(dkimHdr) + "\r\n" + fixture))
	aar, ams, as, err := arc.SealSet(msg, priv, arc.SealOptions{
		Domain: "forwarder.example", Selector: "arc1",
		T:           time.Unix(1057982500, 0),
		AuthResults: "dkim=pass header.d=football.example.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	for _, h := range [][]byte{aar, ams, as} {
		b.Write(h)
		b.WriteString("\r\n")
	}
	b.Write(dkimHdr)
	b.WriteString("\r\n")
	b.WriteString(fixture)
	eml := filepath.Join(dir, "signed.eml")
	if err := os.WriteFile(eml, []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}

	// DKIM t= is 2003; the Date is the only other reference, so drift between
	// t= and Date is checked, not absolute epochs.
	rep := validateFile(eml, 24*time.Hour, keyPath, true, "forwarder.example")
	if !rep.Pass {
		t.Fatalf("expected PASS:\nsummary=%s\nchecks=%+v\ndkim=%+v\narc=%+v",
			rep.Summary, rep.Checks, rep.DKIM, rep.ARC)
	}
	if rep.ARC.Status != "pass" || len(rep.DKIM) != 1 || !rep.DKIM[0].Valid {
		t.Fatalf("unexpected verdicts: arc=%s dkim=%+v", rep.ARC.Status, rep.DKIM)
	}
}

// TestValidateUnsignedFails ensures exit-status semantics: a message with no
// DKIM/ARC must not pass.
func TestValidateUnsignedFails(t *testing.T) {
	dir := t.TempDir()
	eml := filepath.Join(dir, "plain.eml")
	if err := os.WriteFile(eml, []byte(fixture), 0o644); err != nil {
		t.Fatal(err)
	}
	rep := validateFile(eml, time.Minute, "", true, "")
	if rep.Pass {
		t.Fatal("unsigned message must not pass")
	}
}

func TestValidate_AuthenticationResultsDiscrepancy(t *testing.T) {
	dir := t.TempDir()
	// An unsigned message claiming dkim=pass in Authentication-Results
	spoofed := "Authentication-Results: mx.google.com; dkim=pass header.d=football.example.com\r\n" + fixture
	eml := filepath.Join(dir, "spoofed.eml")
	if err := os.WriteFile(eml, []byte(spoofed), 0o644); err != nil {
		t.Fatal(err)
	}
	rep := validateFile(eml, time.Minute, "", true, "mx.google.com")
	if rep.Pass {
		t.Fatal("spoofed auth results should fail validation")
	}
	if len(rep.AuthResults) != 1 {
		t.Fatalf("expected 1 auth result, got %d", len(rep.AuthResults))
	}
	if rep.AuthResults[0].DKIMMatch {
		t.Errorf("DKIMMatch should be false when declared=pass but no valid DKIM")
	}
	if len(rep.AuthResults[0].Discrepancies) == 0 {
		t.Errorf("expected discrepancy message")
	}
}

func TestValidate_GoogleSmtpSourceCaptured(t *testing.T) {
	dir := t.TempDir()
	withGoogle := "X-Google-Smtp-Source: AGHT+IFxR8w1JkX6y3m+Z1a8bC9dEfGhIjKlMnOpQrStUvWxYz0123456789==\r\n" + fixture
	eml := filepath.Join(dir, "google.eml")
	if err := os.WriteFile(eml, []byte(withGoogle), 0o644); err != nil {
		t.Fatal(err)
	}
	rep := validateFile(eml, time.Minute, "", true, "")
	if len(rep.GoogleSource) != 1 {
		t.Fatalf("expected 1 Google source header, got %d", len(rep.GoogleSource))
	}
	if rep.GoogleSource[0].Status != "opaque_provider_metadata" {
		t.Errorf("status = %q, want opaque_provider_metadata", rep.GoogleSource[0].Status)
	}
}
