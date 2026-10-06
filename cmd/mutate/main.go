// Command mutate modifies email bodies and headers, and can atomically
// re-sign DKIM, seal fresh ARC hops, or append multi-hop ARC sets.
package main

import (
	"crypto"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"gbm.dev/emltools/internal/arc"
	"gbm.dev/emltools/internal/dkimcore"
	"gbm.dev/emltools/internal/googlesmtp"
	"gbm.dev/emltools/internal/mailmsg"
	"gbm.dev/emltools/internal/mutate"
)

type mutateOptions struct {
	replacePair string // "old:new"
	appendBody  string
	prependBody string
	addHeader   string // "Name: Value"
	rmHeader    string // "Name"
	stripAuth   bool
	stripDKIM   bool
	stripARC    bool
	mockGoogle  bool
	domain      string
	selector    string
	keyPath     string
	redkim      bool
	appendArc   bool
	arcSeal     bool
	tFlag       int64
	canon       string
	hlist       string
	length      int
	authResults string
}

func runMutate(raw []byte, o mutateOptions) ([]byte, error) {
	raw = toCRLF(raw)
	msg, err := mailmsg.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("parse input: %w", err)
	}

	mOpts := mutate.Options{
		ReplaceText: make(map[string]string),
	}

	if o.replacePair != "" {
		oldStr, newStr, found := strings.Cut(o.replacePair, ":")
		if found {
			mOpts.ReplaceText[oldStr] = newStr
		}
	}
	if o.appendBody != "" {
		mOpts.AppendBody = o.appendBody
	}
	if o.prependBody != "" {
		mOpts.PrependBody = o.prependBody
	}
	if o.rmHeader != "" {
		mOpts.HeadersToRemove = append(mOpts.HeadersToRemove, o.rmHeader)
	}
	if o.stripAuth || o.stripDKIM || o.stripARC {
		mOpts.HeadersToRemove = append(mOpts.HeadersToRemove, mutate.AuthHeaderNames(mutate.StripOptions{
			AllAuth: o.stripAuth,
			DKIM:    o.stripDKIM,
			ARC:     o.stripARC,
		})...)
	}
	if o.addHeader != "" {
		k, v, found := strings.Cut(o.addHeader, ":")
		if found {
			mOpts.HeadersToAdd = append(mOpts.HeadersToAdd, [2]string{strings.TrimSpace(k), strings.TrimSpace(v)})
		}
	}
	if o.mockGoogle {
		mockVal := googlesmtp.GenerateMock(48, "")
		mOpts.HeadersToAdd = append(mOpts.HeadersToAdd, [2]string{"X-Google-Smtp-Source", mockVal})
	}

	mutated, err := mutate.Apply(msg, mOpts)
	if err != nil {
		return nil, fmt.Errorf("mutate: %w", err)
	}

	var key crypto.Signer
	if o.keyPath != "" {
		keyBytes, err := os.ReadFile(o.keyPath)
		if err != nil {
			return nil, fmt.Errorf("read key: %w", err)
		}
		key, err = dkimcore.PrivateKeyFromPEM(keyBytes)
		if err != nil {
			return nil, fmt.Errorf("parse key: %w", err)
		}
	}

	signTime := time.Now()
	if o.tFlag > 0 {
		signTime = time.Unix(o.tFlag, 0)
	} else if d := mutated.Date(); !d.IsZero() {
		signTime = d
	}

	hc, bc := splitCanon(o.canon)
	headers := strings.Split(o.hlist, ":")
	if len(headers) == 1 && headers[0] == "" {
		headers = []string{"from", "to", "subject", "date", "message-id"}
	}

	if o.appendArc && key != nil {
		aarPayload := o.authResults
		if aarPayload == "" {
			aarPayload = "arc=pass; dkim=fail (body modified)"
		}
		appendedMsg, err := arc.AppendHop(mutated, key, arc.SealOptions{
			Domain:        o.domain,
			Selector:      o.selector,
			T:             signTime,
			AuthResults:   aarPayload,
			AMSHeaderList: headers,
		}, nil)
		if err != nil {
			return nil, fmt.Errorf("append-arc: %w", err)
		}
		return appendedMsg.Raw, nil
	}

	if o.redkim && key != nil {
		// Strip stale DKIM and ARC headers
		base := stripStale(mutated)
		baseMsg, err := mailmsg.Parse(base)
		if err != nil {
			return nil, err
		}

		dkimHdr, err := dkimcore.Sign(baseMsg, key, dkimcore.SignOptions{
			Domain:      o.domain,
			Selector:    o.selector,
			HeaderCanon: hc,
			BodyCanon:   bc,
			HeaderList:  headers,
			T:           signTime,
			Length:      o.length,
		})
		if err != nil {
			return nil, err
		}

		var arcBlock []byte
		if o.arcSeal {
			sealed, err := mailmsg.Parse(append([]byte(string(dkimHdr)+"\r\n"), base...))
			if err != nil {
				return nil, err
			}
			aarPayload := o.authResults
			if aarPayload == "" {
				aarPayload = "dkim=pass"
			}
			aar, ams, as, err := arc.SealSet(sealed, key, arc.SealOptions{
				Domain:        o.domain,
				Selector:      o.selector,
				T:             signTime,
				AuthResults:   aarPayload,
				AMSHeaderList: headers,
			})
			if err != nil {
				return nil, err
			}
			for _, h := range [][]byte{aar, ams, as} {
				arcBlock = append(arcBlock, h...)
				arcBlock = append(arcBlock, '\r', '\n')
			}
		}

		result := append(arcBlock, string(dkimHdr)+"\r\n"...)
		return append(result, base...), nil
	}

	return mutated.Raw, nil
}

func stripStale(msg *mailmsg.Message) []byte {
	stale := map[string]bool{
		"dkim-signature":             true,
		"arc-authentication-results": true,
		"arc-message-signature":      true,
		"arc-seal":                   true,
	}
	var b strings.Builder
	for _, h := range msg.Headers {
		if stale[strings.ToLower(h.Name)] {
			continue
		}
		b.Write(h.Raw)
		b.WriteString("\r\n")
	}
	b.WriteString("\r\n")
	b.Write(msg.RawBody)
	return []byte(b.String())
}

func splitCanon(c string) (string, string) {
	if c == "" {
		return "relaxed", "relaxed"
	}
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

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: mutate <msg.eml> [options]")
		os.Exit(2)
	}

	fs := flag.NewFlagSet("mutate", flag.ExitOnError)
	replacePair := fs.String("replace", "", "replace text as 'old:new'")
	appendBody := fs.String("append-body", "", "text to append to body")
	prependBody := fs.String("prepend-body", "", "text to prepend to body")
	addHdr := fs.String("add-header", "", "header to add as 'Name: Value'")
	rmHdr := fs.String("rm-header", "", "header name to remove")
	stripAuth := fs.Bool("strip-auth", false, "strip DKIM, ARC, and Authentication-Results headers")
	stripDKIM := fs.Bool("strip-dkim", false, "strip DKIM-Signature headers")
	stripARC := fs.Bool("strip-arc", false, "strip ARC headers")
	mockGoogle := fs.Bool("mock-google", false, "insert synthetic X-Google-Smtp-Source header")
	outPath := fs.String("o", "", "output file path (default: stdout)")

	// Signing / ARC options
	keyPath := fs.String("key", "", "PEM private key for re-signing")
	domain := fs.String("d", "", "signing domain")
	selector := fs.String("s", "", "signing selector")
	redkim := fs.Bool("redkim", false, "re-sign DKIM with specified key")
	arcSeal := fs.Bool("arc", false, "seal fresh ARC set at i=1")
	appendArc := fs.Bool("append-arc", false, "append forwarding ARC hop (i=N+1)")
	canon := fs.String("c", "relaxed/relaxed", "canonicalization header/body")
	hlist := fs.String("h", "from:to:subject:date:message-id", "headers to sign")
	tFlag := fs.Int64("t", 0, "signature timestamp (default: Date header epoch)")
	length := fs.Int("l", 0, "DKIM body length limit (l= octets)")
	aar := fs.String("aar", "", "ARC-Authentication-Results payload")

	fs.Parse(os.Args[2:])
	file := os.Args[1]

	raw, err := os.ReadFile(file)
	if err != nil {
		fmt.Fprintf(os.Stderr, "mutate: %v\n", err)
		os.Exit(1)
	}

	o := mutateOptions{
		replacePair: *replacePair,
		appendBody:  *appendBody,
		prependBody: *prependBody,
		addHeader:   *addHdr,
		rmHeader:    *rmHdr,
		stripAuth:   *stripAuth,
		stripDKIM:   *stripDKIM,
		stripARC:    *stripARC,
		mockGoogle:  *mockGoogle,
		domain:      *domain,
		selector:    *selector,
		keyPath:     *keyPath,
		redkim:      *redkim,
		appendArc:   *appendArc,
		arcSeal:     *arcSeal,
		tFlag:       *tFlag,
		canon:       *canon,
		hlist:       *hlist,
		length:      *length,
		authResults: *aar,
	}

	res, err := runMutate(raw, o)
	if err != nil {
		fmt.Fprintf(os.Stderr, "mutate: %v\n", err)
		os.Exit(1)
	}

	if *outPath == "" {
		os.Stdout.Write(res)
		return
	}
	if err := os.WriteFile(*outPath, res, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "mutate: %v\n", err)
		os.Exit(1)
	}
}
