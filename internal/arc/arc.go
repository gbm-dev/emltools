// Package arc implements ARC chain collection, validation, and sealing
// (RFC 8617).
package arc

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
	"time"

	"gbm.dev/emltools/internal/dkimcanon"
	"gbm.dev/emltools/internal/dkimcore"
	"gbm.dev/emltools/internal/mailmsg"
)

// Set is one ARC Set: AAR + AMS + AS sharing an instance tag.
type Set struct {
	I   int
	AAR *mailmsg.Header
	AMS *dkimcore.Sig
	AS  *dkimcore.Sig
}

// Result is the outcome of chain validation (RFC 8617 §6).
type Result struct {
	Status     string // "none" | "pass" | "fail"
	Sets       []Set
	AMS        []*dkimcore.VerifyResult
	AS         []*SealResult
	OldestPass int // 0 = every AMS verified; else lowest AMS instance that failed + 1
	Errs       []string
}

// SealResult is the outcome of one ARC-Seal check.
type SealResult struct {
	I      int
	Domain string
	CV     string
	Valid  bool
	Errs   []string
}

func (r *Result) fail(format string, args ...any) {
	r.Errs = append(r.Errs, fmt.Sprintf(format, args...))
}

// instanceOf extracts the i= tag from an AAR header value ("i=1; ...").
func instanceOf(v string) int {
	if _, after, ok := strings.Cut(strings.TrimSpace(v), "i="); ok {
		tok := after
		if j := strings.IndexAny(tok, ";\t "); j >= 0 {
			tok = tok[:j]
		}
		if n, err := strconv.Atoi(strings.TrimSpace(tok)); err == nil {
			return n
		}
	}
	return 0
}

// Collect gathers ARC sets in instance order, reporting malformed headers.
func Collect(msg *mailmsg.Message) ([]Set, []string) {
	var errs []string
	aars := msg.GetAll("ARC-Authentication-Results")
	var amss, ass []*dkimcore.Sig
	for _, h := range msg.GetAll("ARC-Message-Signature") {
		s, err := dkimcore.ParseSig("ARC-Message-Signature", h.Raw)
		if err != nil {
			errs = append(errs, err.Error())
			continue
		}
		amss = append(amss, s)
	}
	for _, h := range msg.GetAll("ARC-Seal") {
		s, err := dkimcore.ParseSig("ARC-Seal", h.Raw)
		if err != nil {
			errs = append(errs, err.Error())
			continue
		}
		ass = append(ass, s)
	}

	maxI := 0
	for _, h := range aars {
		if n := instanceOf(h.Value); n > maxI {
			maxI = n
		}
	}
	for _, s := range append(amss, ass...) {
		if s.Instance() > maxI {
			maxI = s.Instance()
		}
	}

	sets := make([]Set, 0, maxI)
	for i := 1; i <= maxI; i++ {
		set := Set{I: i}
		for _, h := range aars {
			if instanceOf(h.Value) == i {
				set.AAR = &h
				break
			}
		}
		for _, s := range amss {
			if s.Instance() == i {
				set.AMS = s
				break
			}
		}
		for _, s := range ass {
			if s.Instance() == i {
				set.AS = s
				break
			}
		}
		sets = append(sets, set)
	}
	return sets, errs
}

// Validate runs the RFC 8617 §6 validator algorithm.
func Validate(msg *mailmsg.Message, lookup dkimcore.KeyLookup) *Result {
	res := &Result{Status: "none"}
	sets, errs := Collect(msg)
	res.Sets = sets
	res.Errs = append(res.Errs, errs...)
	if len(sets) == 0 {
		if len(errs) > 0 {
			res.Status = "fail"
		}
		return res
	}
	n := sets[len(sets)-1].I
	if len(sets) > 50 {
		res.Status = "fail"
		res.fail("more than 50 ARC sets")
		return res
	}
	if len(sets) != n {
		res.Status = "fail"
		res.fail("ARC set instances are not a contiguous 1..%d sequence", n)
		return res
	}

	// §6.3 structural checks
	for _, set := range sets {
		if set.AAR == nil || set.AMS == nil || set.AS == nil {
			res.Status = "fail"
			res.fail("ARC set i=%d is incomplete (AAR=%t AMS=%t AS=%t)",
				set.I, set.AAR != nil, set.AMS != nil, set.AS != nil)
			continue
		}
		want := "pass"
		if set.I == 1 {
			want = "none"
		}
		cv := strings.ToLower(strings.TrimSpace(set.AS.Tags["cv"]))
		switch {
		case cv == "fail":
			res.Status = "fail"
			res.fail("ARC-Seal i=%d records cv=fail", set.I)
		case cv != want:
			res.fail("ARC-Seal i=%d has cv=%s, want %s", set.I, cv, want)
		}
	}
	if res.Status == "fail" {
		return res
	}

	// §6.4: validate the most recent AMS; failure fails the chain.
	last := sets[len(sets)-1]
	amsRes := last.AMS.Verify(msg, lookup)
	res.AMS = append(res.AMS, amsRes)
	if !amsRes.Valid {
		res.Status = "fail"
		res.fail("AMS i=%d failed validation: %v", last.I, amsRes.Errs)
		return res
	}

	// §6.5: oldest-pass, recorded but not chain-fatal.
	for i := len(sets) - 2; i >= 0; i-- {
		r := sets[i].AMS.Verify(msg, lookup)
		res.AMS = append(res.AMS, r)
		if !r.Valid {
			res.OldestPass = sets[i].I + 1
			break
		}
	}

	// §6.6: validate each AS from N down to 1; any failure fails the chain.
	for i := len(sets) - 1; i >= 0; i-- {
		r := verifySeal(msg, sets, sets[i], lookup)
		res.AS = append(res.AS, r)
		if !r.Valid {
			res.Status = "fail"
			res.fail("ARC-Seal i=%d failed validation: %v", sets[i].I, r.Errs)
			return res
		}
	}
	res.Status = "pass"
	return res
}

// sealInput builds the ARC-Seal hash input for instance i (RFC 8617 §5.1.1):
// relaxed-canonicalized AAR, AMS, AS(b= intact) for instances 1..i-1, then
// AAR_i, AMS_i, then the current AS with b= blanked (curSealBlanked). No
// trailing CRLF on the final header.
func sealInput(sets []Set, i int, curSealBlanked []byte) []byte {
	var buf bytes.Buffer
	for _, set := range sets {
		if set.I >= i {
			break
		}
		buf.Write(relaxed("ARC-Authentication-Results", set.AAR.Raw))
		buf.Write(relaxed("ARC-Message-Signature", set.AMS.Raw))
		buf.Write(relaxed("ARC-Seal", set.AS.Raw))
	}
	cur := sets[i-1]
	buf.Write(relaxed("ARC-Authentication-Results", cur.AAR.Raw))
	buf.Write(relaxed("ARC-Message-Signature", cur.AMS.Raw))
	// RFC 8617 §5.1.1: the blanked current seal is last, with no trailing CRLF.
	buf.Write(bytes.TrimSuffix(relaxed("ARC-Seal", curSealBlanked), []byte("\r\n")))
	return buf.Bytes()
}

// relaxed canonicalizes one raw header line (which includes its "Name:" prefix)
// in relaxed form, CRLF-terminated.
func relaxed(name string, raw []byte) []byte {
	_, val, _ := strings.Cut(string(raw), ":")
	return dkimcanon.HeaderRelaxed(name, dkimcanon.Unfold(val))
}

// verifySeal checks one ARC-Seal.
func verifySeal(msg *mailmsg.Message, sets []Set, set Set, lookup dkimcore.KeyLookup) *SealResult {
	r := &SealResult{
		I:      set.I,
		Domain: set.AS.Tag("d"),
		CV:     strings.ToLower(strings.TrimSpace(set.AS.Tags["cv"])),
	}
	if set.AS.Tags["h"] != "" {
		r.Errs = append(r.Errs, "ARC-Seal carries a forbidden h= tag (RFC 8617 §4.1.3)")
		return r
	}
	if set.AS.Tags["bh"] != "" {
		r.Errs = append(r.Errs, "ARC-Seal carries a forbidden bh= tag")
		return r
	}
	algo := strings.ToLower(set.AS.Tags["a"])
	sel := set.AS.Tag("s")
	b := set.AS.Tag("b")
	if algo == "" || r.Domain == "" || sel == "" || b == "" {
		r.Errs = append(r.Errs, "ARC-Seal missing a=/d=/s=/b= tag")
		return r
	}
	sig, err := base64.StdEncoding.DecodeString(b)
	if err != nil {
		r.Errs = append(r.Errs, "b= base64: "+err.Error())
		return r
	}
	pub, _, err := lookup(sel, r.Domain)
	if err != nil {
		r.Errs = append(r.Errs, "key lookup: "+err.Error())
		return r
	}
	data := sealInput(sets, set.I, dkimcore.BlankB(set.AS.Raw))
	if err := dkimcore.VerifyDetached(algo, data, sig, pub); err != nil {
		r.Errs = append(r.Errs, err.Error())
		return r
	}
	r.Valid = true
	return r
}

// ---------- sealing (for cmd/sign and tests) ----------

// SealOptions configures SealSet.
type SealOptions struct {
	Domain, Selector string
	Instance         int // 0 = len(Chain)+1
	T                time.Time
	AuthResults      string // AAR payload after "i=N; "
	AMSHeaderList    []string
	Chain            []Set // existing chain being sealed over; empty for i=1
}

// SealSet generates one ARC set (AAR, AMS, AS) over msg. Returned headers are
// raw texts without trailing CRLF, in prepend order (AAR, AMS, AS).
func SealSet(msg *mailmsg.Message, key crypto.Signer, o SealOptions) (aar, ams, as []byte, err error) {
	if o.Instance <= 0 {
		existing, _ := Collect(msg)
		o.Instance = len(existing) + 1
		if len(o.Chain)+1 > o.Instance {
			o.Instance = len(o.Chain) + 1
		}
	}
	cv := "pass"
	if o.Instance == 1 {
		cv = "none"
	}
	now := o.T
	if now.IsZero() {
		now = time.Now()
	}
	algo := "rsa-sha256"
	if _, ok := key.(ed25519.PrivateKey); ok {
		algo = "ed25519-sha256"
	} else if _, ok := key.(*rsa.PrivateKey); !ok {
		return nil, nil, nil, fmt.Errorf("unsupported signer type %T", key)
	}

	aar = []byte(fmt.Sprintf("ARC-Authentication-Results: i=%d; %s", o.Instance, o.AuthResults))

	amsList := o.AMSHeaderList
	if len(amsList) == 0 {
		amsList = []string{"from", "to", "subject", "date", "message-id", "dkim-signature"}
	}
	ams, err = dkimcore.Sign(msg, key, dkimcore.SignOptions{
		HeaderName:  "ARC-Message-Signature",
		Domain:      o.Domain,
		Selector:    o.Selector,
		HeaderCanon: "relaxed",
		BodyCanon:   "relaxed",
		HeaderList:  amsList,
		T:           now,
		Instance:    o.Instance,
	})
	if err != nil {
		return nil, nil, nil, err
	}

	// Working copy whose headers include the new AAR + AMS so the seal input
	// sees the exact bytes being sealed.
	block := bytes.NewBuffer(nil)
	block.Write(aar)
	block.WriteString("\r\n")
	block.Write(ams)
	block.WriteString("\r\n")
	block.Write(msg.RawHeader)
	work, err := mailmsg.Parse(append(block.Bytes(), append([]byte("\r\n"), msg.RawBody...)...))
	if err != nil {
		return nil, nil, nil, err
	}
	workSets, _ := Collect(work)
	sealText := fmt.Sprintf("ARC-Seal: i=%d; a=%s; cv=%s; d=%s; s=%s; t=%d; b=",
		o.Instance, algo, cv, o.Domain, o.Selector, now.Unix())
	input := sealInput(workSets, o.Instance, []byte(sealText))
	sig, err := dkimcore.SignDetached(algo, input, key)
	if err != nil {
		return nil, nil, nil, err
	}
	as = []byte(sealText + fold64(base64.StdEncoding.EncodeToString(sig)))
	return aar, ams, as, nil
}

// AppendHop validates the existing ARC chain on arrival, creates a new ARC set
// for instance N+1, and returns a new parsed Message with the new ARC headers
// prepended in RFC 8617 order (AAR, AMS, AS).
func AppendHop(msg *mailmsg.Message, key crypto.Signer, o SealOptions, lookup dkimcore.KeyLookup) (*mailmsg.Message, error) {
	existingSets, errs := Collect(msg)
	if len(errs) > 0 {
		return nil, fmt.Errorf("arc: malformed existing ARC sets: %s", strings.Join(errs, "; "))
	}
	nextI := len(existingSets) + 1
	o.Instance = nextI

	// If there are existing sets, default AuthResults to arrival assessment if not given
	if nextI > 1 && o.AuthResults == "" {
		if lookup != nil {
			res := Validate(msg, lookup)
			if res.Status == "pass" {
				o.AuthResults = "arc=pass"
			} else {
				o.AuthResults = fmt.Sprintf("arc=fail (%s)", strings.Join(res.Errs, "; "))
			}
		} else {
			o.AuthResults = "arc=pass"
		}
	} else if o.AuthResults == "" {
		o.AuthResults = "dkim=pass"
	}

	aar, ams, as, err := SealSet(msg, key, o)
	if err != nil {
		return nil, err
	}

	var block bytes.Buffer
	for _, h := range [][]byte{aar, ams, as} {
		block.Write(h)
		block.WriteString("\r\n")
	}
	block.Write(msg.Raw)

	return mailmsg.Parse(block.Bytes())
}

func fold64(b string) string {
	var out strings.Builder
	for len(b) > 60 {
		out.WriteString(b[:60])
		out.WriteString("\r\n\t")
		b = b[60:]
	}
	out.WriteString(b)
	return out.String()
}
