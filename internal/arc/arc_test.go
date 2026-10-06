package arc

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"gbm.dev/emltools/internal/dkimcore"
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

// withDKIM prepends a DKIM-Signature so AMS has one to cover.
func withDKIM(t *testing.T, key ed25519.PrivateKey, msg *mailmsg.Message) string {
	t.Helper()
	hdr, err := dkimcore.Sign(msg, key, dkimcore.SignOptions{
		Domain: "football.example.com", Selector: "mta",
		HeaderCanon: "relaxed", BodyCanon: "relaxed",
		T: time.Unix(1117574938, 0),
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(hdr) + "\r\n" + string(msg.Raw)
}

func sealAndPrepend(t *testing.T, key ed25519.PrivateKey, raw string, opts SealOptions) string {
	t.Helper()
	msg := mustMsg(t, raw)
	aar, ams, as, err := SealSet(msg, key, opts)
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	for _, h := range [][]byte{aar, ams, as} {
		b.Write(h)
		b.WriteString("\r\n")
	}
	b.WriteString(raw)
	return b.String()
}

func TestSealValidateOneHop(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	base := withDKIM(t, priv, mustMsg(t, fixture))
	signed := sealAndPrepend(t, priv, base, SealOptions{
		Domain: "forwarder.example", Selector: "arc1",
		T:           time.Unix(1117575000, 0),
		AuthResults: "dkim=pass header.d=football.example.com",
	})
	msg := mustMsg(t, signed)
	res := Validate(msg, dkimcore.StaticKeyLookup(publicOf(priv)))
	if res.Status != "pass" {
		t.Fatalf("chain status = %s, errs=%v", res.Status, res.Errs)
	}
	if len(res.AMS) != 1 || !res.AMS[0].Valid {
		t.Fatalf("AMS results: %+v", res.AMS)
	}
	if len(res.AS) != 1 || !res.AS[0].Valid {
		t.Fatalf("AS results: %+v", res.AS)
	}
}

func TestSealValidateTwoHops(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	base := withDKIM(t, priv, mustMsg(t, fixture))
	hop1 := sealAndPrepend(t, priv, base, SealOptions{
		Domain: "forwarder1.example", Selector: "arc1",
		T:           time.Unix(1117575000, 0),
		AuthResults: "dkim=pass header.d=football.example.com",
	})
	hop2 := sealAndPrepend(t, priv, hop1, SealOptions{
		Domain: "forwarder2.example", Selector: "arc2",
		T:           time.Unix(1117576000, 0),
		AuthResults: "arc=pass",
	})
	res := Validate(mustMsg(t, hop2), dkimcore.StaticKeyLookup(publicOf(priv)))
	if res.Status != "pass" {
		t.Fatalf("chain status = %s, errs=%v", res.Status, res.Errs)
	}
	if len(res.Sets) != 2 || res.Sets[1].I != 2 {
		t.Fatalf("sets = %+v", res.Sets)
	}
	if res.OldestPass != 0 {
		t.Fatalf("oldest-pass = %d, want 0", res.OldestPass)
	}
}

func TestTamperAARFailsChain(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	base := withDKIM(t, priv, mustMsg(t, fixture))
	signed := sealAndPrepend(t, priv, base, SealOptions{
		Domain: "forwarder.example", Selector: "arc1",
		T:           time.Unix(1117575000, 0),
		AuthResults: "dkim=pass header.d=football.example.com",
	})
	forged := strings.Replace(signed,
		"ARC-Authentication-Results: i=1; dkim=pass",
		"ARC-Authentication-Results: i=1; dkim=fail", 1)
	res := Validate(mustMsg(t, forged), dkimcore.StaticKeyLookup(publicOf(priv)))
	if res.Status != "fail" {
		t.Fatalf("forged AAR should fail the chain, got %s (%v)", res.Status, res.Errs)
	}
}

func TestStructuralFailures(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	lookup := dkimcore.StaticKeyLookup(publicOf(priv))

	// cv=fail recorded on i=1
	base := withDKIM(t, priv, mustMsg(t, fixture))
	msg := mustMsg(t, sealAndPrepend(t, priv, base, SealOptions{
		Domain: "f.example", Selector: "s",
		AuthResults: "dkim=pass",
	}))
	badCV := strings.Replace(string(msg.Raw), "cv=none", "cv=fail", 1)
	if res := Validate(mustMsg(t, badCV), lookup); res.Status != "fail" {
		t.Fatalf("cv=fail on i=1 should fail, got %s", res.Status)
	}

	// gap: AMS i=1 + AS i=1 but AAR missing
	gapped := strings.Replace(string(msg.Raw), "ARC-Authentication-Results: i=1; dkim=pass\r\n", "", 1)
	res := Validate(mustMsg(t, gapped), lookup)
	if res.Status != "fail" {
		t.Fatalf("missing AAR should fail, got %s", res.Status)
	}
}

func TestNoARCHeaders(t *testing.T) {
	res := Validate(mustMsg(t, fixture), nil)
	if res.Status != "none" {
		t.Fatalf("status = %s, want none", res.Status)
	}
}

func TestAppendHop_ModifiedBodySurvives(t *testing.T) {
	_, priv1, _ := ed25519.GenerateKey(rand.Reader)
	_, priv2, _ := ed25519.GenerateKey(rand.Reader)

	// Step 1: Message with original DKIM and sealed with hop 1
	base := withDKIM(t, priv1, mustMsg(t, fixture))
	hop1Raw := sealAndPrepend(t, priv1, base, SealOptions{
		Domain:      "origin.example",
		Selector:    "arc1",
		T:           time.Unix(1117575000, 0),
		AuthResults: "dkim=pass header.d=football.example.com",
	})
	hop1Msg := mustMsg(t, hop1Raw)

	// Step 2: An intermediary modifies the body (appends footer)
	modifiedBody := string(hop1Msg.RawBody) + "\r\n-- \r\nForwarded by Mailing List\r\n"
	modifiedRaw := string(hop1Msg.RawHeader) + "\r\n\r\n" + modifiedBody
	modifiedMsg := mustMsg(t, modifiedRaw)

	// Step 3: Intermediary appends hop 2 sealing over the modified body
	multikeyLookup := func(sel, domain string) (crypto.PublicKey, string, error) {
		if domain == "origin.example" {
			return publicOf(priv1), "priv1", nil
		}
		if domain == "list.example" {
			return publicOf(priv2), "priv2", nil
		}
		return publicOf(priv1), "priv1", nil
	}

	hop2Msg, err := AppendHop(modifiedMsg, priv2, SealOptions{
		Domain:      "list.example",
		Selector:    "arc2",
		T:           time.Unix(1117576000, 0),
		AuthResults: "arc=pass; dkim=fail (body modified)",
	}, multikeyLookup)
	if err != nil {
		t.Fatalf("AppendHop failed: %v", err)
	}

	// Step 4: Validate resulting multi-hop message
	res := Validate(hop2Msg, multikeyLookup)
	if res.Status != "pass" {
		t.Fatalf("chain status = %s, want pass, errs=%v", res.Status, res.Errs)
	}
	if len(res.Sets) != 2 {
		t.Fatalf("expected 2 sets, got %d", len(res.Sets))
	}
	// OldestPass should be 2 because hop 1 AMS failed against the modified body
	if res.OldestPass != 2 {
		t.Errorf("OldestPass = %d, want 2", res.OldestPass)
	}
	// The latest AMS (hop 2) must be valid
	if len(res.AMS) < 1 || !res.AMS[0].Valid {
		t.Errorf("latest AMS failed: %+v", res.AMS)
	}
	// Both seals must be valid
	for _, s := range res.AS {
		if !s.Valid {
			t.Errorf("seal i=%d invalid: %+v", s.I, s.Errs)
		}
	}
}

func publicOf(priv ed25519.PrivateKey) ed25519.PublicKey {
	return priv.Public().(ed25519.PublicKey)
}
