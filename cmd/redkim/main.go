// Command redkim strips stale DKIM-Signature and ARC-* headers from an .eml,
// re-signs DKIM, and optionally seals a fresh ARC set (i=1), so a message
// edited or retimed after signing validates again. By default t= is taken
// from the Date header epoch, keeping t= drift at zero after a retime.
package main

import (
	"bytes"
	"crypto"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"gbm.dev/emltools/internal/arc"
	"gbm.dev/emltools/internal/dkimcore"
	"gbm.dev/emltools/internal/mailmsg"
)

// staleHeaders are removed before re-signing: a broken signature is as
// damaging as none, so re-signing never leaves stale ones in place.
var staleHeaders = []string{
	"DKIM-Signature",
	"ARC-Authentication-Results",
	"ARC-Message-Signature",
	"ARC-Seal",
}

func isStale(name string) bool {
	for _, s := range staleHeaders {
		if strings.EqualFold(name, s) {
			return true
		}
	}
	return false
}

// stripStale rebuilds the raw header block without stale headers, each kept
// header CRLF-terminated. The blank separator line is not included.
func stripStale(msg *mailmsg.Message) []byte {
	var b bytes.Buffer
	for i := range msg.Headers {
		if isStale(msg.Headers[i].Name) {
			continue
		}
		b.Write(msg.Headers[i].Raw)
		b.WriteString("\r\n")
	}
	return b.Bytes()
}

// Options configures redkim.
type Options struct {
	Domain, Selector       string
	HeaderCanon, BodyCanon string
	HeaderList             []string
	T, X                   time.Time
	ARC                    bool
	AuthResults            string // AAR payload used with ARC
}

// redkim strips stale DKIM/ARC headers, re-signs DKIM and, with o.ARC, seals
// a fresh ARC set at i=1. When o.T is zero, t= defaults to the Date header
// epoch. The output is CRLF-normalized.
func redkim(raw []byte, key crypto.Signer, o Options) ([]byte, error) {
	raw = toCRLF(raw)
	msg, err := mailmsg.Parse(raw)
	if err != nil {
		return nil, err
	}
	if o.T.IsZero() {
		if d := msg.Date(); !d.IsZero() {
			o.T = d
		}
	}

	base := append(append(stripStale(msg), '\r', '\n'), msg.RawBody...)
	stripped, err := mailmsg.Parse(base)
	if err != nil {
		return nil, err
	}
	dkimHdr, err := dkimcore.Sign(stripped, key, dkimcore.SignOptions{
		Domain: o.Domain, Selector: o.Selector,
		HeaderCanon: o.HeaderCanon, BodyCanon: o.BodyCanon,
		HeaderList: o.HeaderList, T: o.T, X: o.X,
	})
	if err != nil {
		return nil, err
	}

	var block []byte
	if o.ARC {
		sealed, err := mailmsg.Parse(append([]byte(string(dkimHdr)+"\r\n"), base...))
		if err != nil {
			return nil, err
		}
		aar, ams, as, err := arc.SealSet(sealed, key, arc.SealOptions{
			Domain: o.Domain, Selector: o.Selector,
			T:           o.T,
			AuthResults: o.AuthResults,
		})
		if err != nil {
			return nil, err
		}
		for _, h := range [][]byte{aar, ams, as} {
			block = append(block, h...)
			block = append(block, '\r', '\n')
		}
	}

	result := append(block, string(dkimHdr)+"\r\n"...)
	return append(result, base...), nil
}

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	flags, rest := partition(os.Args[1:])
	fs := flag.NewFlagSet("redkim", flag.ExitOnError)
	domain := fs.String("d", "", "signing domain (d=)")
	selector := fs.String("s", "", "selector (s=)")
	keyPath := fs.String("key", "", "PEM private key (PKCS#8/PKCS#1/ed25519)")
	canon := fs.String("c", "relaxed/relaxed", "canonicalization header/body")
	hlist := fs.String("h", "from:to:subject:date:message-id", "headers to sign")
	tFlag := fs.Int64("t", 0, "signature timestamp (default: Date header epoch)")
	expiry := fs.Int64("x", 0, "signature expiry (unix ts, 0 = omit)")
	arcSeal := fs.Bool("arc", false, "also attach a fresh ARC set (AAR, AMS, AS) at i=1")
	authRes := fs.String("aar", "dkim=pass", "AAR payload used with -arc")
	out := fs.String("out", "", "output path (default: stdout)")
	fs.Parse(flags)
	if len(rest) != 1 || *domain == "" || *selector == "" || *keyPath == "" {
		usage()
	}
	key, err := dkimcore.PrivateKeyFromPEM(mustRead(*keyPath))
	if err != nil {
		fatal(err)
	}
	hc, bc := splitCanon(*canon)
	o := Options{
		Domain: *domain, Selector: *selector,
		HeaderCanon: hc, BodyCanon: bc,
		HeaderList:  strings.Split(*hlist, ":"),
		ARC:         *arcSeal,
		AuthResults: *authRes,
	}
	if *tFlag > 0 {
		o.T = time.Unix(*tFlag, 0)
	}
	if *expiry > 0 {
		o.X = time.Unix(*expiry, 0)
	}
	raw, err := os.ReadFile(rest[0])
	if err != nil {
		fatal(err)
	}
	result, err := redkim(raw, key, o)
	if err != nil {
		fatal(err)
	}
	if *out == "" {
		os.Stdout.Write(result)
		return
	}
	if err := os.WriteFile(*out, result, 0o644); err != nil {
		fatal(err)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: redkim msg.eml -d example.com -s sel -key key.pem [-c relaxed/relaxed] [-h from:to:...] [-t 1694720139] [-arc]")
	os.Exit(2)
}

// partition splits args into flag arguments and positionals, tolerating flags
// placed after positional arguments (Go's flag package stops at the first
// non-flag argument). Flags are value-taking unless listed as boolean.
func partition(args []string) (flags, rest []string) {
	boolean := map[string]bool{"-arc": true, "--arc": true}
	for i := 0; i < len(args); i++ {
		a := args[i]
		if strings.HasPrefix(a, "-") && a != "-" {
			flags = append(flags, a)
			if !boolean[a] && i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				i++
				flags = append(flags, args[i])
			}
			continue
		}
		rest = append(rest, a)
	}
	return flags, rest
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
	fmt.Fprintln(os.Stderr, "redkim:", err)
	os.Exit(1)
}
