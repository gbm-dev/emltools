package main

import (
	"crypto"
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

func encodePrivPEM(priv ed25519.PrivateKey) []byte {
	der, _ := x509.MarshalPKCS8PrivateKey(priv)
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

func encodePubPEM(pub ed25519.PublicKey) []byte {
	der, _ := x509.MarshalPKIXPublicKey(pub)
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}

const fixture = "From: Joe SixPack <joe@football.example.com>\r\n" +
	"To: Suzie Q <suzie@shopping.example.net>\r\n" +
	"Subject: Is dinner ready?\r\n" +
	"Date: Fri, 11 Jul 2003 21:00:37 -0700 (PDT)\r\n" +
	"Message-ID: <20030712040037.46341.5F8J@football.example.com>\r\n" +
	"\r\n" +
	"Hi.\r\n\r\nWe lost the game. Are you hungry yet?\r\n\r\nJoe.\r\n"

func TestMutateCLI_ReplaceAndResign(t *testing.T) {
	dir := t.TempDir()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	privPEM := encodePrivPEM(priv)
	keyPath := filepath.Join(dir, "key.pem")
	_ = os.WriteFile(keyPath, privPEM, 0o600)

	inPath := filepath.Join(dir, "input.eml")
	_ = os.WriteFile(inPath, []byte(fixture), 0o644)
	outPath := filepath.Join(dir, "output.eml")

	opts := mutateOptions{
		replacePair: "hungry:STARVING",
		domain:      "football.example.com",
		selector:    "test",
		keyPath:     keyPath,
		redkim:      true,
		tFlag:       1057982437,
	}

	raw, err := os.ReadFile(inPath)
	if err != nil {
		t.Fatal(err)
	}

	result, err := runMutate(raw, opts)
	if err != nil {
		t.Fatalf("runMutate failed: %v", err)
	}
	_ = os.WriteFile(outPath, result, 0o644)

	resMsg, err := mailmsg.Parse(result)
	if err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(string(resMsg.RawBody), "STARVING") {
		t.Errorf("expected body to contain STARVING")
	}

	// Verify DKIM signature with public key
	sigs := resMsg.GetAll("DKIM-Signature")
	if len(sigs) != 1 {
		t.Fatalf("expected 1 DKIM-Signature, got %d", len(sigs))
	}
	sig, _ := dkimcore.ParseSig("DKIM-Signature", sigs[0].Raw)
	v := sig.Verify(resMsg, dkimcore.StaticKeyLookup(pub))
	if !v.Valid {
		t.Fatalf("verification failed: %v", v.Errs)
	}
}

func TestMutateCLI_AppendArcHop(t *testing.T) {
	dir := t.TempDir()
	pub1, priv1, _ := ed25519.GenerateKey(rand.Reader)
	_, priv2, _ := ed25519.GenerateKey(rand.Reader)
	priv2PEM := encodePrivPEM(priv2)
	key2Path := filepath.Join(dir, "key2.pem")
	_ = os.WriteFile(key2Path, priv2PEM, 0o600)

	// Create initial message with hop 1
	msg := mustMsg(t, fixture)
	aar, ams, as, err := arc.SealSet(msg, priv1, arc.SealOptions{
		Domain:      "origin.example",
		Selector:    "arc1",
		T:           time.Unix(1057982500, 0),
		AuthResults: "dkim=pass",
	})
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	for _, h := range [][]byte{aar, ams, as} {
		b.Write(h)
		b.WriteString("\r\n")
	}
	b.WriteString(fixture)
	hop1Raw := []byte(b.String())

	// Mutate: append footer and append ARC hop 2
	opts := mutateOptions{
		appendBody: "\r\n--\r\nForwarded via List\r\n",
		domain:     "list.example",
		selector:   "arc2",
		keyPath:    key2Path,
		appendArc:  true,
		tFlag:      1057982600,
	}

	result, err := runMutate(hop1Raw, opts)
	if err != nil {
		t.Fatalf("runMutate failed: %v", err)
	}

	resMsg, err := mailmsg.Parse(result)
	if err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(string(resMsg.RawBody), "Forwarded via List") {
		t.Errorf("missing appended footer")
	}

	sets, _ := arc.Collect(resMsg)
	if len(sets) != 2 {
		t.Fatalf("expected 2 ARC sets, got %d", len(sets))
	}

	lookup := func(sel, domain string) (crypto.PublicKey, string, error) {
		if domain == "origin.example" {
			return pub1, "pub1", nil
		}
		return priv2.Public(), "pub2", nil
	}
	arcRes := arc.Validate(resMsg, lookup)
	if arcRes.Status != "pass" {
		t.Fatalf("ARC validation failed: %s (%v)", arcRes.Status, arcRes.Errs)
	}
}

func mustMsg(t *testing.T, raw string) *mailmsg.Message {
	t.Helper()
	m, err := mailmsg.Parse([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestMutateCLI_StripAuth(t *testing.T) {
	msgWithAuth := "From: test@example.com\r\n" +
		"DKIM-Signature: v=1; a=rsa-sha256; d=example.com; b=123\r\n" +
		"ARC-Seal: i=1; a=rsa-sha256; d=example.com; b=456\r\n" +
		"Authentication-Results: mx.google.com; dkim=pass\r\n" +
		"\r\n" +
		"Hello world\r\n"

	out, err := runMutate([]byte(msgWithAuth), mutateOptions{
		stripAuth: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if strings.Contains(s, "DKIM-Signature:") || strings.Contains(s, "ARC-Seal:") || strings.Contains(s, "Authentication-Results:") {
		t.Fatalf("expected all auth headers to be stripped, got:\n%s", s)
	}
	if !strings.Contains(s, "From: test@example.com") {
		t.Errorf("expected From header to remain")
	}
}
