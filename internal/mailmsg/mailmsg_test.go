package mailmsg

import (
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

const confirmSample = "../../Order Confirmation for City of Miami 2026 _ Lifeguard Training - Gibson Pool.eml"

func load(t *testing.T, path string) *Message {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("fixture not available: %v", err)
	}
	m, err := Parse(b)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return m
}

func TestParseConfirmSample(t *testing.T) {
	m := load(t, confirmSample)
	if got := m.Get("Delivered-To"); got != "nelsonperez6906@gmail.com" {
		t.Fatalf("Delivered-To = %q", got)
	}
	if got := m.Get("Subject"); got == "" {
		t.Fatal("subject empty; unfolding broken")
	}
}

func TestDecodeMSFBL(t *testing.T) {
	m := load(t, confirmSample)
	x, err := m.DecodeMSFBL()
	if err != nil {
		t.Fatal(err)
	}
	if x.CustomerID != "274689" || x.TenantID != "spc" || x.Subaccount != "12" {
		t.Fatalf("msfbl = %+v", x)
	}
	if x.MessageID != "6aa87dc3aa6a76b656a5" {
		t.Fatalf("message_id = %q", x.MessageID)
	}
	sec, err := x.Epoch()
	if err != nil {
		t.Fatal(err)
	}
	want := time.Unix(1789427139, 0).UTC()
	if got := time.Unix(sec, 0).UTC(); !got.Equal(want) {
		t.Fatalf("epoch = %v, want %v", got, want)
	}
}

func TestStampsConfirmSample(t *testing.T) {
	m := load(t, confirmSample)
	st := m.Stamps()
	bySource := map[string]Stamp{}
	for _, s := range st {
		bySource[s.Source] = s
	}
	cases := []struct {
		src  string
		want time.Time
	}{
		{"X-MSFBL.message_id", time.Unix(1789427139, 0).UTC()},
		{"Date", time.Unix(1788113677, 0).UTC()},
		{"Message-ID.seed", time.Unix(1788113677, 0).UTC()},
		{"X-Received.tail", time.UnixMilli(1788113678000).UTC()},
	}
	for _, c := range cases {
		s, ok := bySource[c.src]
		if !ok {
			t.Fatalf("missing stamp %s (have %v)", c.src, keys(bySource))
		}
		if !s.When.Equal(c.want) {
			t.Errorf("%s = %v, want %v", c.src, s.When, c.want)
		}
	}
	// mx.google dotted id: 2026.08.30.11.14.38 in -0700
	mx, ok := bySource["Received[2].mxid"]
	if !ok {
		t.Fatalf("missing mxid stamp (have %v)", keys(bySource))
	}
	if got := mx.When.UTC(); got.Unix() != 1788087278 {
		t.Errorf("mxid utc = %v (%d), want %d", got, got.Unix(), 1788087278)
	}
}

func keys(m map[string]Stamp) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestParseHeaderOnlyAndCRLF(t *testing.T) {
	raw := []byte("From: a@b.c\r\nSubject: hi\r\n\r\nbody\r\n")
	m, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if m.Get("Subject") != "hi" || string(m.RawBody) != "body\r\n" {
		t.Fatalf("mismatch: %q / %q", m.Get("Subject"), m.RawBody)
	}
}

func TestFoldedHeaderRawPreservesCRLF(t *testing.T) {
	raw := []byte("DKIM-Signature: v=1; a=rsa-sha256;\r\n\td=example.com;\r\n\tb=abc\r\n\r\nx\r\n")
	m, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	h := m.GetAll("DKIM-Signature")[0]
	want := "DKIM-Signature: v=1; a=rsa-sha256;\r\n\td=example.com;\r\n\tb=abc"
	if string(h.Raw) != want {
		t.Fatalf("Raw = %q, want %q", h.Raw, want)
	}
}

// TestFormatRFC2822LikeKeepsTheOriginalShape pins the three formatting choices
// a reformatting pass must not make on its own: the day's padding, the UTC
// offset exactly as written, and any trailing zone comment.
//
// The offset text matters beyond looks. RFC 5322 §3.3 gives "-0000" the meaning
// "no information about the sender's zone", which is a different claim from the
// "+0000" that asserts UTC; time.Time carries the instant and not that
// distinction, so the text has to come from the string being replaced.
func TestFormatRFC2822LikeKeepsTheOriginalShape(t *testing.T) {
	target := time.Date(2026, 9, 8, 12, 0, 2, 0, time.UTC)
	tests := []struct {
		name string
		like string
		t    time.Time
		want string
	}{
		{
			name: "unpadded day stays unpadded, -0000 kept",
			like: "Thu, 3 Sep 2026 16:35:21 -0000",
			t:    target,
			want: "Tue, 8 Sep 2026 12:00:02 -0000",
		},
		{
			name: "padded day stays padded",
			like: "Thu, 03 Sep 2026 16:35:21 -0000",
			t:    target,
			want: "Tue, 08 Sep 2026 12:00:02 -0000",
		},
		{
			name: "+0000 is not rewritten to -0000 or vice versa",
			like: "Sun, 30 Aug 2026 18:14:37 +0000",
			t:    target,
			want: "Tue, 8 Sep 2026 12:00:02 +0000",
		},
		{
			name: "zone comment and its offset survive the move",
			like: "Wed, 16 Sep 2026 09:35:23 -0700 (PDT)",
			t:    target,
			want: "Tue, 8 Sep 2026 05:00:02 -0700 (PDT)",
		},
		{
			name: "no weekday stays absent",
			like: "3 Sep 2026 16:35:21 -0000",
			t:    target,
			want: "8 Sep 2026 12:00:02 -0000",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := FormatRFC2822Like(tc.t, tc.like); got != tc.want {
				t.Errorf("FormatRFC2822Like(%v, %q) = %q, want %q", tc.t, tc.like, got, tc.want)
			}
		})
	}
}

// TestFormatRFC2822DoesNotZeroPadTheDay guards the fallback path: no Eventbrite
// or SparkPost message on hand writes "03 Sep", and a retime that introduces the
// padding has marked the header as regenerated.
func TestFormatRFC2822DoesNotZeroPadTheDay(t *testing.T) {
	got := FormatRFC2822(time.Date(2026, 9, 3, 16, 35, 21, 0, time.UTC))
	if strings.Contains(got, "03 Sep") {
		t.Errorf("FormatRFC2822 zero-padded the day: %q", got)
	}
}

// TestParseZone pins the zone grammar retime's --zone accepts: the RFC 5322
// §3.3 forms plus IANA names, with the military single-letter zones the RFC
// says SHOULD NOT be used refused outright.
func TestParseZone(t *testing.T) {
	tests := []struct {
		in     string
		offset int // seconds east of UTC, or -1 when an error is wanted
		name   string
	}{
		{in: "-0700", offset: -7 * 3600},
		{in: "+0530", offset: 5*3600 + 30*60},
		{in: "PDT", offset: -7 * 3600, name: "PDT"},
		{in: "pdt", offset: -7 * 3600, name: "PDT"},
		{in: "EST", offset: -5 * 3600, name: "EST"},
		{in: "GMT", offset: 0, name: "GMT"},
		{in: "", offset: 0},
		{in: "America/Los_Angeles", offset: -7 * 3600, name: "PDT"}, // DST on 2026-09-16
		{in: "America/New_York", offset: -4 * 3600, name: "EDT"},
		// zone = 4DIGIT in RFC 5322 §3.3; the ISO 8601 "+HH:MM" spelling is
		// not one of its forms.
		{in: "-07:00", offset: -1},
		{in: "Z", offset: -1},
		{in: "X", offset: -1},
		{in: "Not/AZone", offset: -1},
	}
	for _, tc := range tests {
		loc, err := ParseZone(tc.in)
		if tc.offset == -1 {
			if err == nil {
				t.Errorf("ParseZone(%q) accepted a zone it must refuse", tc.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseZone(%q): %v", tc.in, err)
			continue
		}
		at := time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)
		if got := at.In(loc).Format("-0700"); got != formatOffset(tc.offset) {
			t.Errorf("ParseZone(%q) offset = %s, want %s", tc.in, got, formatOffset(tc.offset))
		}
		if tc.name != "" {
			if got := zoneAbbrev(loc, at); got != tc.name {
				t.Errorf("ParseZone(%q) abbreviation = %q, want %q", tc.in, got, tc.name)
			}
		}
	}
}

func formatOffset(secs int) string {
	sign := "+"
	if secs < 0 {
		sign, secs = "-", -secs
	}
	return fmt.Sprintf("%s%02d%02d", sign, secs/3600, secs%3600/60)
}

// TestFormatRFC2822LikeInRendersTheNamedZone: a date rendered with an explicit
// zone states that zone's offset and abbrev, not the original's.
func TestFormatRFC2822LikeInRendersTheNamedZone(t *testing.T) {
	at := time.Date(2026, 8, 30, 18, 14, 37, 0, time.UTC)
	tests := []struct {
		like string // the shape the original was written in
		zone string
		want string
	}{
		{"Sun, 30 Aug 2026 18:14:37 +0000", "-0700", "Sun, 30 Aug 2026 11:14:37 -0700"},
		// The original's comment is a claim about its own zone, so --zone
		// replaces it with the named zone's abbreviation...
		{"Sun, 30 Aug 2026 18:14:37 +0000 (UTC)", "PDT", "Sun, 30 Aug 2026 11:14:37 -0700 (PDT)"},
		{"Sun, 30 Aug 2026 18:14:37 -0000", "PDT", "Sun, 30 Aug 2026 11:14:37 -0700"},
		// ...and an original with no comment stays commentless: a comment is
		// never manufactured. (The shape carries padding and zone text only;
		// day, month and weekday always come from the instant.)
		{"Thu, 3 Sep 2026 16:35:21 +0000", "PDT", "Sun, 30 Aug 2026 11:14:37 -0700"},
		// A padded original stays padded.
		{"Sun, 03 Aug 2026 18:14:37 +0000", "-0700", "Sun, 30 Aug 2026 11:14:37 -0700"},
	}
	for _, tc := range tests {
		loc, err := ParseZone(tc.zone)
		if err != nil {
			t.Fatalf("ParseZone(%q): %v", tc.zone, err)
		}
		got := FormatRFC2822LikeIn(at, tc.like, loc)
		if got != tc.want {
			t.Errorf("FormatRFC2822LikeIn(at, %q, %q) = %q, want %q", tc.like, tc.zone, got, tc.want)
		}
	}
}

// TestFormatRFC2822LikeKeepsZoneOnlyDateShape: with no zone named, a Date
// whose original carries no comment is rendered with no comment, which is the
// shape the delivered messages' Date headers are in.
func TestFormatRFC2822LikeKeepsZoneOnlyDateShape(t *testing.T) {
	at := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	got := FormatRFC2822Like(at, "Tue, 8 Sep 2026 12:00:00 +0000")
	if got != "Tue, 8 Sep 2026 12:00:00 +0000" {
		t.Errorf("identity round trip = %q", got)
	}
}
