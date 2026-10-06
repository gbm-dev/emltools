// Command sign adds a DKIM-Signature (and optionally an ARC set) to an .eml,
// producing fixtures for the validator. The output is CRLF-normalized, since
// canonicalization assumes wire format.
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"gbm.dev/emltools/internal/arc"
	"gbm.dev/emltools/internal/dkimcore"
	"gbm.dev/emltools/internal/mailmsg"
)

func main() {
	in := flag.String("in", "", "input .eml")
	out := flag.String("out", "", "output path (default: stdout)")
	domain := flag.String("d", "", "signing domain (d=)")
	selector := flag.String("s", "", "selector (s=)")
	keyPath := flag.String("key", "", "PEM private key (PKCS#8/PKCS#1/ed25519)")
	canon := flag.String("c", "relaxed/relaxed", "canonicalization header/body")
	hlist := flag.String("h", "from:to:subject:date:message-id", "headers to sign")
	now := flag.Int64("t", time.Now().Unix(), "signature timestamp")
	expiry := flag.Int64("x", 0, "signature expiry (unix ts, 0 = omit)")
	arcSeal := flag.Bool("arc", false, "also attach an ARC set (AAR, AMS, AS) for i=1")
	authRes := flag.String("aar", "dkim=pass", "AAR payload used with --arc")
	flag.Parse()
	if *in == "" || *domain == "" || *selector == "" || *keyPath == "" {
		fmt.Fprintln(os.Stderr, "usage: sign -in msg.eml -d example.com -s sel -key key.pem [-c relaxed/relaxed] [-h from:to:...] [-arc]")
		os.Exit(2)
	}
	raw, err := os.ReadFile(*in)
	if err != nil {
		fatal(err)
	}
	raw = toCRLF(raw)
	msg, err := mailmsg.Parse(raw)
	if err != nil {
		fatal(err)
	}
	key, err := dkimcore.PrivateKeyFromPEM(mustRead(*keyPath))
	if err != nil {
		fatal(err)
	}
	hc, bc := splitCanon(*canon)

	opts := dkimcore.SignOptions{
		Domain: *domain, Selector: *selector,
		HeaderCanon: hc, BodyCanon: bc,
		HeaderList: strings.Split(*hlist, ":"),
		T:          time.Unix(*now, 0),
	}
	if *expiry > 0 {
		opts.X = time.Unix(*expiry, 0)
	}
	dkimHdr, err := dkimcore.Sign(msg, key, opts)
	if err != nil {
		fatal(err)
	}
	msg, err = mailmsg.Parse(append([]byte(string(dkimHdr)+"\r\n"), raw...))
	if err != nil {
		fatal(err)
	}

	var result []byte
	if *arcSeal {
		aar, ams, as, err := arc.SealSet(msg, key, arc.SealOptions{
			Domain: *domain, Selector: *selector,
			T:           time.Unix(*now, 0),
			AuthResults: *authRes,
		})
		if err != nil {
			fatal(err)
		}
		for _, h := range [][]byte{aar, ams, as} {
			result = append(result, h...)
			result = append(result, '\r', '\n')
		}
	}
	// DKIM-Signature, then original message (prefixed with ARC headers if -arc)
	result = append(result, dkimHdr...)
	result = append(result, '\r', '\n')
	result = append(result, raw...)
	if *out == "" {
		os.Stdout.Write(result)
		return
	}
	if err := os.WriteFile(*out, result, 0o644); err != nil {
		fatal(err)
	}
}

func mustRead(path string) []byte {
	b, err := os.ReadFile(path)
	if err != nil {
		fatal(err)
	}
	return b
}

func splitCanon(c string) (string, string) {
	parts := strings.SplitN(c, "/", 2)
	hc := strings.ToLower(parts[0])
	bc := "simple"
	if len(parts) == 2 {
		bc = strings.ToLower(parts[1])
	}
	return hc, bc
}

func toCRLF(b []byte) []byte {
	s := strings.ReplaceAll(string(b), "\r\n", "\n")
	return []byte(strings.ReplaceAll(s, "\n", "\r\n"))
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "sign:", err)
	os.Exit(1)
}
