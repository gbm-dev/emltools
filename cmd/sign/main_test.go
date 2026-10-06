package main

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"

	"gbm.dev/emltools/internal/arc"
	"gbm.dev/emltools/internal/dkimcore"
	"gbm.dev/emltools/internal/mailmsg"
)

func TestSplitCanon(t *testing.T) {
	tests := []struct {
		in    string
		wantH string
		wantB string
	}{
		{"relaxed/relaxed", "relaxed", "relaxed"},
		{"simple/simple", "simple", "simple"},
		{"relaxed/simple", "relaxed", "simple"},
		{"relaxed", "relaxed", "simple"},
	}
	for _, tc := range tests {
		h, b := splitCanon(tc.in)
		if h != tc.wantH || b != tc.wantB {
			t.Errorf("splitCanon(%q) = (%q, %q), want (%q, %q)", tc.in, h, b, tc.wantH, tc.wantB)
		}
	}
}

func TestToCRLF(t *testing.T) {
	input := []byte("hello\nworld\r\nfoo\n")
	got := toCRLF(input)
	want := []byte("hello\r\nworld\r\nfoo\r\n")
	if !bytes.Equal(got, want) {
		t.Fatalf("toCRLF failed: got %q, want %q", got, want)
	}
}

func TestSignAndVerifyRoundtrip(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})

	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "priv.pem")
	if err := os.WriteFile(keyPath, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}

	rawEmail := []byte("From: alice@example.com\r\nTo: bob@example.com\r\nSubject: Test\r\nDate: Mon, 14 Sep 2026 12:00:00 +0000\r\n\r\nBody line 1\r\n")
	msg, err := mailmsg.Parse(rawEmail)
	if err != nil {
		t.Fatal(err)
	}

	key, err := dkimcore.PrivateKeyFromPEM(pemBytes)
	if err != nil {
		t.Fatal(err)
	}

	opts := dkimcore.SignOptions{
		Domain:      "example.com",
		Selector:    "sel1",
		HeaderCanon: "relaxed",
		BodyCanon:   "relaxed",
		HeaderList:  []string{"from", "to", "subject", "date"},
		T:           time.Unix(1700000000, 0),
	}

	dkimHdr, err := dkimcore.Sign(msg, key, opts)
	if err != nil {
		t.Fatal(err)
	}

	// Verify the signed message
	signedRaw := append(dkimHdr, '\r', '\n')
	signedRaw = append(signedRaw, rawEmail...)

	signedMsg, err := mailmsg.Parse(signedRaw)
	if err != nil {
		t.Fatal(err)
	}

	lookup := func(sel, dom string) (crypto.PublicKey, string, error) {
		return pub, "pub", nil
	}

	sigs := signedMsg.GetAll("DKIM-Signature")
	if len(sigs) != 1 {
		t.Fatalf("expected 1 DKIM-Signature, got %d", len(sigs))
	}
	sig, err := dkimcore.ParseSig("DKIM-Signature", sigs[0].Raw)
	if err != nil {
		t.Fatal(err)
	}
	res := sig.Verify(signedMsg, lookup)
	if !res.Valid {
		t.Fatalf("expected valid signature, got errors: %v", res.Errs)
	}

	// Now verify with ARC
	aar, ams, as, err := arc.SealSet(signedMsg, key, arc.SealOptions{
		Domain:      "example.com",
		Selector:    "sel1",
		T:           time.Unix(1700000000, 0),
		AuthResults: "dkim=pass header.i=@example.com",
	})
	if err != nil {
		t.Fatal(err)
	}

	var arcBlock []byte
	for _, h := range [][]byte{aar, ams, as} {
		arcBlock = append(arcBlock, h...)
		arcBlock = append(arcBlock, '\r', '\n')
	}
	fullRaw := append(arcBlock, signedRaw...)

	fullMsg, err := mailmsg.Parse(fullRaw)
	if err != nil {
		t.Fatal(err)
	}

	arcRes := arc.Validate(fullMsg, lookup)
	if arcRes.Status != "pass" {
		t.Fatalf("expected ARC pass, got status %q: %v", arcRes.Status, arcRes.Errs)
	}
}
