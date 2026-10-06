package authres

import (
	"testing"
)

func TestParse_GoogleStandard(t *testing.T) {
	raw := `Authentication-Results: mx.google.com;
       dkim=pass header.i=@eventbrite.com header.s=mta header.b=AbCd;
       spf=pass (google.com: domain of bounce@bounce.eventbrite.com designates 156.70.3.137 as permitted sender) smtp.mailfrom=bounce@bounce.eventbrite.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=eventbrite.com;
       arc=pass (i=1)`

	h, err := Parse(raw)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	if h.AuthservID != "mx.google.com" {
		t.Fatalf("want authserv-id mx.google.com, got %q", h.AuthservID)
	}
	if len(h.Results) != 4 {
		t.Fatalf("want 4 results, got %d", len(h.Results))
	}

	dkim := h.Result("dkim")
	if dkim == nil {
		t.Fatal("missing dkim result")
	}
	if dkim.Result != "pass" {
		t.Errorf("dkim.Result = %q, want pass", dkim.Result)
	}
	if dkim.Props["header.i"] != "@eventbrite.com" {
		t.Errorf("dkim props header.i = %q, want @eventbrite.com", dkim.Props["header.i"])
	}
	if dkim.Props["header.s"] != "mta" {
		t.Errorf("dkim props header.s = %q, want mta", dkim.Props["header.s"])
	}

	spf := h.Result("spf")
	if spf == nil {
		t.Fatal("missing spf result")
	}
	if spf.Result != "pass" {
		t.Errorf("spf.Result = %q, want pass", spf.Result)
	}
	if spf.Props["smtp.mailfrom"] != "bounce@bounce.eventbrite.com" {
		t.Errorf("spf props smtp.mailfrom = %q", spf.Props["smtp.mailfrom"])
	}
	if spf.Comment == "" {
		t.Errorf("expected spf comment to be preserved")
	}

	dmarc := h.Result("dmarc")
	if dmarc == nil || dmarc.Result != "pass" || dmarc.Props["header.from"] != "eventbrite.com" {
		t.Errorf("dmarc result invalid: %+v", dmarc)
	}

	arc := h.Result("arc")
	if arc == nil || arc.Result != "pass" {
		t.Errorf("arc result invalid: %+v", arc)
	}
}

func TestParse_VersionAndReason(t *testing.T) {
	raw := `Authentication-Results: example.org 1;
       dkim=fail reason="bad signature" (key expired) header.d=bad.example header.b=1234;
       spf=softfail smtp.mailfrom=user@bad.example`

	h, err := Parse(raw)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	if h.AuthservID != "example.org" {
		t.Errorf("authserv-id = %q, want example.org", h.AuthservID)
	}
	if h.Version != 1 {
		t.Errorf("version = %d, want 1", h.Version)
	}
	dkim := h.Result("dkim")
	if dkim == nil || dkim.Result != "fail" {
		t.Fatalf("dkim result: %+v", dkim)
	}
	if dkim.Reason != "bad signature" {
		t.Errorf("reason = %q, want 'bad signature'", dkim.Reason)
	}
	if dkim.Comment != "key expired" {
		t.Errorf("comment = %q, want 'key expired'", dkim.Comment)
	}
	if dkim.Props["header.d"] != "bad.example" {
		t.Errorf("header.d = %q", dkim.Props["header.d"])
	}
}

func TestCompareDeclaredVsComputed(t *testing.T) {
	raw := `Authentication-Results: mx.google.com; dkim=pass header.d=example.com`
	h, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}

	comp := Compare(h, CompareInput{
		TrustedAuthservIDs: []string{"mx.google.com"},
		DKIMValid:          false,
		DKIMDomain:         "example.com",
		DKIMError:          "body hash mismatch",
		ARCStatus:          "none",
	})

	if !comp.TrustedBoundary {
		t.Errorf("expected mx.google.com to be trusted boundary")
	}
	if comp.DKIMMatch {
		t.Errorf("expected DKIMMatch to be false when declared=pass but computed=fail")
	}
	if len(comp.Discrepancies) == 0 {
		t.Errorf("expected discrepancy reported for DKIM failure")
	}
}

func TestUntrustedBoundary(t *testing.T) {
	raw := `Authentication-Results: untrusted.attacker.com; dkim=pass header.d=bank.com`
	h, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}

	comp := Compare(h, CompareInput{
		TrustedAuthservIDs: []string{"mx.google.com"},
		DKIMValid:          true,
		DKIMDomain:         "bank.com",
	})

	if comp.TrustedBoundary {
		t.Errorf("expected untrusted.attacker.com to NOT be trusted boundary")
	}
}
