// Command validate checks whether the timestamps in an .eml align, and
// reports the state of its DKIM signatures and ARC chain.
//
// Point it at a file; it prints every date it can find (X-MSFBL, Date,
// Message-ID seed, Received dates, X-Received tail, mx.google id, DKIM t=/x=,
// ARC AAR/AMS/AS t=), measures each against the reference (X-MSFBL when
// present, else Date), verifies DKIM body hashes and signatures, and runs the
// RFC 8617 §6 chain validation algorithm.
//
// Exit status: 0 = all checks pass, 1 = any mismatch or verification failure.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"gbm.dev/emltools/internal/arc"
	"gbm.dev/emltools/internal/authres"
	"gbm.dev/emltools/internal/dkimcore"
	"gbm.dev/emltools/internal/googlesmtp"
	"gbm.dev/emltools/internal/mailmsg"
)

type check struct {
	Source string `json:"source"`
	Raw    string `json:"raw"`
	When   string `json:"when"`
	Epoch  int64  `json:"epoch"`
	Drift  string `json:"drift"`
	Delta  int64  `json:"drift_seconds"`
	Status string `json:"status"` // ref | ok | MISMATCH
}

type dkimOut struct {
	Index     int      `json:"index"`
	Domain    string   `json:"domain"`
	Selector  string   `json:"selector"`
	Identity  string   `json:"identity,omitempty"`
	Algo      string   `json:"algo,omitempty"`
	Canon     string   `json:"canon,omitempty"`
	BHValid   bool     `json:"body_hash_ok"`
	Valid     bool     `json:"valid"`
	KeySource string   `json:"key_source"`
	Errs      []string `json:"errors,omitempty"`
}

type arcOut struct {
	Status     string   `json:"status"`
	Sets       int      `json:"sets"`
	OldestPass int      `json:"oldest_pass"`
	Errs       []string `json:"errors,omitempty"`
}

type authReportOut struct {
	HeaderRaw       string                 `json:"raw"`
	AuthservID      string                 `json:"authserv_id"`
	TrustedBoundary bool                   `json:"trusted_boundary"`
	DKIMMatch       bool                   `json:"dkim_match"`
	ARCMatch        bool                   `json:"arc_match"`
	Declared        []authres.MethodResult `json:"declared"`
	Discrepancies   []string               `json:"discrepancies,omitempty"`
}

type report struct {
	File         string                     `json:"file"`
	Reference    string                     `json:"reference"`
	Checks       []check                    `json:"checks"`
	MSFBL        *mailmsg.MSFBL             `json:"x_msfbl,omitempty"`
	DKIM         []dkimOut                  `json:"dkim,omitempty"`
	ARC          *arcOut                    `json:"arc,omitempty"`
	AuthResults  []authReportOut            `json:"auth_results,omitempty"`
	GoogleSource []*googlesmtp.SourceReport `json:"x_google_smtp_source,omitempty"`
	Pass         bool                       `json:"pass"`
	Summary      string                     `json:"summary"`
}

func main() {
	flags, files := partition(os.Args[1:])
	fs := flag.NewFlagSet("validate", flag.ExitOnError)
	jsonOut := fs.Bool("json", false, "machine-readable output")
	tolerance := fs.Duration("tolerance", 2*time.Minute, "max drift considered aligned")
	keyFile := fs.String("key", "", "PEM public key used instead of DNS lookups")
	noDNS := fs.Bool("no-dns", false, "skip DNS key lookups (DKIM/ARC reported as unverifiable)")
	trustedAuth := fs.String("trusted-auth", "mx.google.com", "comma-separated trusted authserv-ids")
	fs.Parse(flags)
	if len(files) < 1 {
		fmt.Fprintln(os.Stderr, "usage: validate [flags] <file.eml>...")
		os.Exit(2)
	}

	allPass := true
	var last report
	for _, path := range files {
		r := validateFile(path, *tolerance, *keyFile, *noDNS, *trustedAuth)
		allPass = allPass && r.Pass
		if *jsonOut {
			last = r
			continue
		}
		printText(r)
	}
	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(last); err != nil {
			fatal(err)
		}
	}
	if !allPass {
		os.Exit(1)
	}
}

// partition splits args into flag arguments and positionals, tolerating flags
// placed after positional arguments (Go's flag package stops at the first
// non-flag argument). Flags are value-taking unless listed as boolean.
func partition(args []string) (flags, rest []string) {
	boolean := map[string]bool{
		"-json": true, "--json": true,
		"-no-dns": true, "--no-dns": true,
	}
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

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "validate:", err)
	os.Exit(2)
}

func validateFile(path string, tolerance time.Duration, keyFile string, noDNS bool, trustedAuth string) report {
	rep := report{File: path, Pass: true}
	raw, err := os.ReadFile(path)
	if err != nil {
		fatal(err)
	}
	msg, err := mailmsg.Parse(raw)
	if err != nil {
		fatal(err)
	}

	// --- reference time ---
	var ref time.Time
	if x, err := msg.DecodeMSFBL(); err == nil {
		rep.MSFBL = x
		if epoch, err := x.Epoch(); err == nil {
			ref = time.Unix(epoch, 0).UTC()
			rep.Reference = "X-MSFBL.message_id"
		}
	}
	if ref.IsZero() {
		ref = msg.Date()
		rep.Reference = "Date"
	}

	addCheck := func(source, rawText string, when time.Time) {
		if when.IsZero() {
			return
		}
		c := check{
			Source: source, Raw: rawText,
			When:  when.UTC().Format(time.RFC3339),
			Epoch: when.UTC().Unix(),
		}
		drift := when.UTC().Sub(ref)
		c.Drift = humanize(drift.Truncate(time.Second))
		c.Delta = int64(drift.Seconds())
		switch {
		case source == rep.Reference:
			c.Status = "ref"
		case drift.Abs() <= tolerance:
			c.Status = "ok"
		default:
			c.Status = "MISMATCH"
			rep.Pass = false
		}
		rep.Checks = append(rep.Checks, c)
	}
	// Stamps() does not report the ecelerity queue ID, whose trailing 8 hex
	// carry the injection time reversed. retime pins it to the target, so after
	// a retime it agrees with the reference by construction and would add no
	// information here; a message that was NOT retimed still passes even though
	// its queue ID sits at the injection time while its Date does not, which is
	// exactly the state this command is meant to catch. Deliberate skip: gating
	// on the queue ID would flip this command's exit status for messages already
	// on disk, which is the operator's call rather than a side effect of adding
	// a retime carrier. Reopen when the operator wants validate to gate on the
	// queue ID, or when a file turns up that passes every check here while its
	// queue ID sits at a different send time.
	for _, s := range msg.Stamps() {
		addCheck(s.Source, s.Raw, s.When)
	}

	// --- key resolution ---
	lookup := dkimcore.KeyLookup(nil)
	switch {
	case keyFile != "":
		data, err := os.ReadFile(keyFile)
		if err != nil {
			fatal(err)
		}
		pub, err := dkimcore.PublicKeyFromPEM(data)
		if err != nil {
			fatal(err)
		}
		lookup = dkimcore.StaticKeyLookup(pub)
	case !noDNS:
		lookup = dkimcore.DNSKeyLookup(nil)
	}

	// --- DKIM ---
	sigs := msg.GetAll("DKIM-Signature")
	if len(sigs) == 0 {
		note := "no DKIM-Signature header"
		if keyFile == "" && !noDNS {
			note += " (Gmail normally preserves the sender's DKIM; its absence is itself a finding)"
		}
		rep.DKIM = []dkimOut{{Errs: []string{note}}}
		rep.Pass = false
	}
	for i, h := range sigs {
		sig, err := dkimcore.ParseSig("DKIM-Signature", h.Raw)
		if err != nil {
			rep.DKIM = append(rep.DKIM, dkimOut{Index: i + 1, Errs: []string{err.Error()}})
			rep.Pass = false
			continue
		}
		res := sig.Verify(msg, lookup)
		out := dkimOut{
			Index: i + 1, Domain: res.Domain, Selector: res.Selector, Identity: res.Identity,
			Algo: res.Algo, Canon: res.Canon, BHValid: res.BHValid, Valid: res.Valid,
			KeySource: res.KeySource, Errs: res.Errs,
		}
		if t, ok := sig.Timestamp(); ok {
			addCheck(fmt.Sprintf("DKIM[%d].t", i+1), t.Format(time.RFC3339), t)
		}
		if x, ok := sig.Expiry(); ok {
			addCheck(fmt.Sprintf("DKIM[%d].x", i+1), x.Format(time.RFC3339), x)
		}
		if !out.Valid {
			rep.Pass = false
		}
		rep.DKIM = append(rep.DKIM, out)
	}

	// --- ARC ---
	chain := arc.Validate(msg, lookup)
	rep.ARC = &arcOut{
		Status:     chain.Status,
		Sets:       len(chain.Sets),
		OldestPass: chain.OldestPass,
		Errs:       chain.Errs,
	}
	for _, s := range chain.Sets {
		if s.AMS != nil {
			if t, ok := s.AMS.Timestamp(); ok {
				addCheck(fmt.Sprintf("ARC-AMS[%d].t", s.I), "", t)
			}
		}
		if s.AS != nil {
			if t, ok := s.AS.Timestamp(); ok {
				addCheck(fmt.Sprintf("ARC-AS[%d].t", s.I), "", t)
			}
		}
	}
	switch chain.Status {
	case "none":
		rep.ARC.Errs = append(rep.ARC.Errs, "no ARC headers present")
	case "pass":
	default:
		rep.Pass = false
	}

	// --- Authentication-Results ---
	var trustedList []string
	if trustedAuth != "" {
		for _, t := range strings.Split(trustedAuth, ",") {
			if s := strings.TrimSpace(t); s != "" {
				trustedList = append(trustedList, s)
			}
		}
	}
	for _, h := range msg.GetAll("Authentication-Results") {
		parsed, err := authres.Parse(h.Value)
		if err != nil {
			continue
		}
		dkimValid := len(rep.DKIM) > 0 && rep.DKIM[0].Valid
		dkimDomain := ""
		dkimErr := ""
		if len(rep.DKIM) > 0 {
			dkimDomain = rep.DKIM[0].Domain
			if len(rep.DKIM[0].Errs) > 0 {
				dkimErr = strings.Join(rep.DKIM[0].Errs, "; ")
			}
		}
		comp := authres.Compare(parsed, authres.CompareInput{
			TrustedAuthservIDs: trustedList,
			DKIMValid:          dkimValid,
			DKIMDomain:         dkimDomain,
			DKIMError:          dkimErr,
			ARCStatus:          chain.Status,
		})
		out := authReportOut{
			HeaderRaw:       h.Value,
			AuthservID:      parsed.AuthservID,
			TrustedBoundary: comp.TrustedBoundary,
			DKIMMatch:       comp.DKIMMatch,
			ARCMatch:        comp.ARCMatch,
			Declared:        parsed.Results,
			Discrepancies:   comp.Discrepancies,
		}
		if !comp.DKIMMatch || !comp.ARCMatch {
			rep.Pass = false
		}
		rep.AuthResults = append(rep.AuthResults, out)
	}

	// --- X-Google-Smtp-Source ---
	rep.GoogleSource = googlesmtp.Extract(msg)

	if rep.Pass {
		rep.Summary = "PASS: timestamps aligned, DKIM and ARC verified"
	} else {
		rep.Summary = "FAIL: see flagged rows above"
	}
	return rep
}

// humanize renders a duration as d/h/m/s instead of Go's hour-based form.
func humanize(d time.Duration) string {
	sign := ""
	if d < 0 {
		sign = "-"
		d = -d
	}
	days := int64(d.Hours()) / 24
	h, m, s := int64(d.Hours())%24, int64(d.Minutes())%60, int64(d.Seconds())%60
	switch {
	case days > 0:
		return fmt.Sprintf("%s%dd%dh%dm%ds", sign, days, h, m, s)
	case h > 0:
		return fmt.Sprintf("%s%dh%dm%ds", sign, h, m, s)
	default:
		return fmt.Sprintf("%s%dm%ds", sign, m, s)
	}
}

func printText(r report) {
	fmt.Printf("FILE: %s\n", r.File)
	fmt.Println("== TIMESTAMPS == (reference: " + r.Reference + ")")
	for _, c := range r.Checks {
		mark := "  "
		switch c.Status {
		case "MISMATCH":
			mark = "!!"
		case "ref":
			mark = "=>"
		}
		fmt.Printf(" %s %-22s %-25s drift=%-14s [%s]\n", mark, c.Source, c.When, c.Drift, c.Status)
	}
	if r.MSFBL != nil {
		fmt.Println("== X-MSFBL ==")
		fmt.Printf("  customer=%s tenant=%s subaccount=%s recipient=%s\n",
			r.MSFBL.CustomerID, r.MSFBL.TenantID, r.MSFBL.Subaccount, r.MSFBL.R)
	}
	fmt.Println("== DKIM ==")
	for _, d := range r.DKIM {
		if d.Domain == "" && d.Selector == "" && len(d.Errs) > 0 {
			fmt.Printf("  MISSING: %s\n", strings.Join(d.Errs, "; "))
			continue
		}
		state := "VERIFIED"
		if !d.Valid {
			state = "FAILED"
		}
		fmt.Printf("  %s d=%s s=%s i=%s algo=%s canon=%s bh=%t key=%s\n",
			state, d.Domain, d.Selector, d.Identity, d.Algo, d.Canon, d.BHValid, d.KeySource)
		for _, e := range d.Errs {
			fmt.Printf("    - %s\n", e)
		}
	}
	fmt.Println("== ARC ==")
	fmt.Printf("  chain=%s sets=%d oldest_pass=%d\n",
		strings.ToUpper(r.ARC.Status), r.ARC.Sets, r.ARC.OldestPass)
	for _, e := range r.ARC.Errs {
		fmt.Printf("    - %s\n", e)
	}
	if len(r.AuthResults) > 0 {
		fmt.Println("== AUTHENTICATION-RESULTS ==")
		for _, a := range r.AuthResults {
			boundary := "UNTRUSTED"
			if a.TrustedBoundary {
				boundary = "TRUSTED"
			}
			fmt.Printf("  authserv-id=%s [%s]\n", a.AuthservID, boundary)
			for _, m := range a.Declared {
				props := ""
				if len(m.Props) > 0 {
					var pList []string
					for k, v := range m.Props {
						pList = append(pList, fmt.Sprintf("%s=%s", k, v))
					}
					props = " " + strings.Join(pList, " ")
				}
				fmt.Printf("    - %s=%s%s\n", m.Method, m.Result, props)
			}
			for _, d := range a.Discrepancies {
				fmt.Printf("    !! DISCREPANCY: %s\n", d)
			}
		}
	}
	if len(r.GoogleSource) > 0 {
		fmt.Println("== X-GOOGLE-SMTP-SOURCE ==")
		for _, g := range r.GoogleSource {
			fmt.Printf("  status=%s valid_base64=%t bytes=%d preview=%s\n",
				g.Status, g.ValidBase64, g.DecodedBytes, g.HexPreview)
			fmt.Printf("    note: %s\n", g.Warning)
		}
	}
	fmt.Printf("== SUMMARY == %s\n\n", r.Summary)
}
