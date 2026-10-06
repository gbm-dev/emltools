package dkimcore_test

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
	"time"

	msgdkim "github.com/emersion/go-msgauth/dkim"

	"gbm.dev/emltools/internal/dkimcore"
	"gbm.dev/emltools/internal/mailmsg"
)

const interopFixture = "From: Joe SixPack <joe@football.example.com>\r\n" +
	"To: Suzie Q <suzie@shopping.example.net>\r\n" +
	"Subject: Is dinner ready?\r\n" +
	"Date: Fri, 11 Jul 2003 21:00:37 -0700 (PDT)\r\n" +
	"Message-ID: <20030712040037.46341.5F8J@football.example.com>\r\n" +
	"X-Custom: folded\r\n value with\ttabs\r\n" +
	"\r\n" +
	"Hi.\r\n\r\nWe lost the game. Are you hungry yet?\r\n\r\nJoe.\r\n"

// txtRecord builds a DKIM DNS TXT record for the given public key. RSA keys
// are SubjectPublicKeyInfo DER (RFC 6376 §3.6.1); ed25519 keys are the raw
// 32 bytes (RFC 8463 §3).
func txtRecord(pub crypto.PublicKey) string {
	if e, ok := pub.(ed25519.PublicKey); ok {
		return fmt.Sprintf("v=DKIM1; k=ed25519; p=%s", base64.StdEncoding.EncodeToString(e))
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		panic(err)
	}
	return fmt.Sprintf("v=DKIM1; k=rsa; p=%s", base64.StdEncoding.EncodeToString(der))
}

// TestInteropOursToMsgauth: signatures produced by dkimcore.Sign must verify
// with the independent emersion/go-msgauth implementation.
func TestInteropOursToMsgauth(t *testing.T) {
	cases := []struct {
		name    string
		canon   string
		makeKey func() (crypto.Signer, crypto.PublicKey)
	}{
		{"rsa-relaxed", "relaxed/relaxed", func() (crypto.Signer, crypto.PublicKey) {
			k, _ := rsa.GenerateKey(rand.Reader, 1024)
			return k, &k.PublicKey
		}},
		{"rsa-simple", "simple/simple", func() (crypto.Signer, crypto.PublicKey) {
			k, _ := rsa.GenerateKey(rand.Reader, 1024)
			return k, &k.PublicKey
		}},
		{"ed25519-relaxed", "relaxed/relaxed", func() (crypto.Signer, crypto.PublicKey) {
			pub, priv, _ := ed25519.GenerateKey(rand.Reader)
			return priv, pub
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			signer, pub := tc.makeKey()
			hc, bc := splitCanon(tc.canon)
			msg, _ := mailmsg.Parse([]byte(interopFixture))
			hdr, err := dkimcore.Sign(msg, signer, dkimcore.SignOptions{
				Domain: "football.example.com", Selector: "interop",
				HeaderCanon: hc, BodyCanon: bc,
				HeaderList: []string{"from", "to", "subject", "date", "message-id", "x-custom"},
				T:          time.Unix(1057982437, 0),
			})
			if err != nil {
				t.Fatal(err)
			}
			signed := string(hdr) + "\r\n" + interopFixture

			verifs, err := msgdkim.VerifyWithOptions(strings.NewReader(signed),
				&msgdkim.VerifyOptions{
					LookupTXT: func(domain string) ([]string, error) {
						return []string{txtRecord(pub)}, nil
					},
				})
			if err != nil {
				t.Fatalf("msgauth verify error: %v", err)
			}
			if len(verifs) != 1 || verifs[0].Err != nil {
				for _, v := range verifs {
					t.Errorf("msgauth verification: domain=%s err=%v", v.Domain, v.Err)
				}
				t.FailNow()
			}
		})
	}
}

// TestInteropMsgauthToOurs: a message signed by emersion/go-msgauth must
// verify with our dkimcore implementation.
func TestInteropMsgauthToOurs(t *testing.T) {
	cases := []struct {
		name    string
		makeKey func() (crypto.Signer, crypto.PublicKey)
	}{
		{"rsa", func() (crypto.Signer, crypto.PublicKey) {
			k, _ := rsa.GenerateKey(rand.Reader, 1024)
			return k, &k.PublicKey
		}},
		{"ed25519", func() (crypto.Signer, crypto.PublicKey) {
			pub, priv, _ := ed25519.GenerateKey(rand.Reader)
			return priv, pub
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			signer, pub := tc.makeKey()
			var buf bytes.Buffer
			err := msgdkim.Sign(&buf, strings.NewReader(interopFixture), &msgdkim.SignOptions{
				Domain:                 "football.example.com",
				Selector:               "interop",
				Signer:                 signer,
				Hash:                   crypto.SHA256,
				HeaderCanonicalization: msgdkim.CanonicalizationRelaxed,
				BodyCanonicalization:   msgdkim.CanonicalizationRelaxed,
				HeaderKeys:             []string{"From", "To", "Subject", "Date", "Message-ID", "X-Custom"},
			})
			if err != nil {
				t.Fatal(err)
			}
			signed := buf.String()

			msg, err := mailmsg.Parse([]byte(signed))
			if err != nil {
				t.Fatal(err)
			}
			hs := msg.GetAll("DKIM-Signature")
			if len(hs) != 1 {
				t.Fatalf("expected 1 signature, got %d", len(hs))
			}
			sig, err := dkimcore.ParseSig("DKIM-Signature", hs[0].Raw)
			if err != nil {
				t.Fatal(err)
			}
			res := sig.Verify(msg, dkimcore.StaticKeyLookup(pub))
			if !res.Valid || !res.BHValid {
				t.Fatalf("our verify of msgauth signature failed: %v (bh=%v)", res.Errs, res.BHValid)
			}
		})
	}
}

func splitCanon(c string) (string, string) {
	parts := strings.SplitN(c, "/", 2)
	return parts[0], parts[1]
}
