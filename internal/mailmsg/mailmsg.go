// Package mailmsg parses raw RFC 5322 messages, preserving raw bytes so
// header rewriting (retime) never touches anything it does not mean to.
package mailmsg

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Header is one message header. Value is the unfolded value (fold CRLF
// removed, leading WSP kept); Raw is the exact source bytes including folds,
// excluding the terminating newline.
type Header struct {
	Name  string
	Value string
	Raw   []byte
}

// Message is a parsed raw message.
type Message struct {
	Raw       []byte
	RawHeader []byte // everything up to and including the blank separator line
	RawBody   []byte
	Headers   []Header
	CRLF      bool // source used CRLF line endings
}

var crlfBlank = []byte("\r\n\r\n")
var lfBlank = []byte("\n\n")

// Parse splits header from body and unfolds headers.
func Parse(raw []byte) (*Message, error) {
	m := &Message{Raw: raw}
	m.CRLF = bytes.Contains(raw, []byte("\r\n"))
	sep := lfBlank
	if m.CRLF {
		sep = crlfBlank
	}
	idx := bytes.Index(raw, sep)
	if idx == -1 {
		m.RawHeader = raw
		m.RawBody = nil
	} else {
		m.RawHeader = raw[:idx]        // up to the blank line, no trailing newline
		m.RawBody = raw[idx+len(sep):] // after the blank line
	}
	m.parseHeaders()
	if len(m.Headers) == 0 {
		return nil, fmt.Errorf("no headers found")
	}
	return m, nil
}

func (m *Message) parseHeaders() {
	var lines [][]byte
	rest := m.RawHeader
	for len(rest) > 0 {
		var line []byte
		if i := bytes.IndexByte(rest, '\n'); i >= 0 {
			line = rest[:i]
			rest = rest[i+1:]
		} else {
			line = rest
			rest = nil
		}
		lines = append(lines, line)
	}
	var cur *Header
	var curRaw []byte
	flush := func() {
		if cur != nil {
			if m.CRLF {
				// preserve wire-format CRLF folds inside Raw
				cur.Raw = bytes.ReplaceAll(curRaw, []byte("\n"), []byte("\r\n"))
			} else {
				cur.Raw = curRaw
			}
			m.Headers = append(m.Headers, *cur)
			cur, curRaw = nil, nil
		}
	}
	for _, line := range lines {
		line = bytes.TrimRight(line, "\r")
		if len(line) > 0 && (line[0] == ' ' || line[0] == '\t') && cur != nil {
			// fold continuation: unfold by dropping the newline only
			curRaw = append(curRaw, '\n')
			curRaw = append(curRaw, line...)
			cur.Value += string(line)
			continue
		}
		flush()
		i := bytes.IndexByte(line, ':')
		if i < 0 {
			continue // garbage line; skip
		}
		name := string(bytes.TrimRight(line[:i], " \t"))
		val := strings.TrimLeft(string(line[i+1:]), " \t")
		cur = &Header{Name: name, Value: val}
		curRaw = append([]byte{}, line...)
	}
	flush()
}

// Get returns the first header value for name (case-insensitive), "" if absent.
func (m *Message) Get(name string) string {
	for _, h := range m.Headers {
		if strings.EqualFold(h.Name, name) {
			return h.Value
		}
	}
	return ""
}

// GetAll returns all headers with the given name in order.
func (m *Message) GetAll(name string) []Header {
	var out []Header
	for _, h := range m.Headers {
		if strings.EqualFold(h.Name, name) {
			out = append(out, h)
		}
	}
	return out
}

// Date returns the parsed Date header, or zero time.
func (m *Message) Date() time.Time {
	d := m.Get("Date")
	if d == "" {
		return time.Time{}
	}
	if t, err := ParseRFC2822(d); err == nil {
		return t
	}
	return time.Time{}
}

var rfc2822Formats = []string{
	"Mon, 2 Jan 2006 15:04:05 -0700",
	"Mon, 02 Jan 2006 15:04:05 -0700",
	"Mon, 2 Jan 2006 15:04:05 MST",
	"Mon, 02 Jan 2006 15:04:05 MST",
	"2 Jan 2006 15:04:05 -0700",
	"Mon, 2 Jan 2006 15:04:05 -0700 (MST)",
}

// ParseRFC2822 parses an RFC 5322 date-time, tolerating a trailing comment.
func ParseRFC2822(s string) (time.Time, error) {
	s = strings.TrimSpace(s)
	// strip trailing comment like "(PDT)"
	if i := strings.LastIndex(s, " ("); i >= 0 && strings.HasSuffix(s, ")") {
		s2 := s[:i]
		if _, err := parseAny(s2); err == nil {
			s = s2
		}
	}
	return parseAny(s)
}

func parseAny(s string) (time.Time, error) {
	var lastErr error
	for _, f := range rfc2822Formats {
		t, err := time.Parse(f, s)
		if err == nil {
			return t, nil
		}
		lastErr = err
	}
	return time.Time{}, lastErr
}

// FormatRFC2822 renders t the way MTAs do (no comment, day not zero-padded).
func FormatRFC2822(t time.Time) string {
	return t.Format("Mon, 2 Jan 2006 15:04:05 -0700")
}

// reRFC2822Parts splits a date-time into the fields a rewrite replaces and the
// fields it must carry through. Group 6 is the zone as the original wrote it and
// group 7 any trailing comment; time.Time cannot reproduce either from the
// parsed value alone.
var reRFC2822Parts = regexp.MustCompile(
	`^(?:([A-Za-z]{3}),[ \t]*)?(\d{1,2})[ \t]+([A-Za-z]{3})[ \t]+(\d{4})[ \t]+` +
		`(\d{2}:\d{2}:\d{2})[ \t]+(\S+?)(?:[ \t]*\(([^)]*)\))?$`)

var reZoneOffset = regexp.MustCompile(`^([+-])(\d{2})(\d{2})$`)

// FormatRFC2822Like renders t as an RFC 5322 date-time shaped like the string it
// replaces: the day keeps the original's padding, the zone is written the way the
// original wrote it, and a trailing zone comment is preserved. The weekday, day,
// month, year and time come from t, rendered in the offset the original named.
//
// Padding is read from a leading zero rather than from the field's width. "16" is
// two characters because sixteen is two digits, not because anything padded it,
// so a two-digit original with no leading zero is treated as unpadded and a
// target landing on the 8th is written "8 Sep".
//
// The zone text has to come from the string rather than from t, because the two
// are not interchangeable: RFC 5322 §3.3 gives "-0000" the meaning "no
// information about the sender's zone", which is a different claim from the
// "+0000" that asserts UTC, and Gmail's "(PDT)" comment is not part of the
// parsed value at all. Reformatting from the parsed time therefore promotes
// "-0000" to "+0000" and drops the comment, both of which are traces the mail
// system did not leave.
//
// A date in a shape this does not recognize, such as one naming an obs-zone
// rather than a numeric offset, falls back to FormatRFC2822.
func FormatRFC2822Like(t time.Time, like string) string {
	return FormatRFC2822LikeIn(t, like, nil)
}

// FormatRFC2822LikeIn is FormatRFC2822Like with the zone named explicitly.
// A nil loc keeps the original's behavior: the date is rendered in the offset
// its own text names, comment included verbatim. A non-nil loc renders the
// instant in that zone instead, and the trailing comment, being a claim about
// the zone, is kept only when the zone's own abbreviation is known and can
// stand in for the original's.
func FormatRFC2822LikeIn(t time.Time, like string, loc *time.Location) string {
	m := reRFC2822Parts.FindStringSubmatch(strings.TrimSpace(like))
	if m == nil {
		return FormatRFC2822(t)
	}
	zoneText := m[6]
	comment := ""
	if m[7] != "" {
		comment = " (" + m[7] + ")"
	}
	if loc == nil {
		z := offsetZone(m[6])
		if z == nil {
			return FormatRFC2822(t)
		}
		loc = z
	} else {
		t = t.In(loc)
		zoneText = t.Format("-0700")
		if m[7] != "" {
			if abbrev := zoneAbbrev(loc, t); abbrev != "" {
				comment = " (" + abbrev + ")"
			} else {
				comment = ""
			}
		}
	}
	t = t.In(loc)

	day := strconv.Itoa(t.Day())
	if m[2][0] == '0' {
		day = fmt.Sprintf("%02d", t.Day())
	}
	weekday := ""
	if m[1] != "" {
		weekday = t.Format("Mon") + ", "
	}
	return fmt.Sprintf("%s%s %s %d %s %s%s",
		weekday, day, t.Format("Jan"), t.Year(), t.Format("15:04:05"), zoneText, comment)
}

// offsetZone builds the fixed zone an offset text names, so a time can be
// rendered in the offset its own header used rather than in whichever zone it
// happens to carry. nil reports text that is not a numeric offset.
func offsetZone(text string) *time.Location {
	m := reZoneOffset.FindStringSubmatch(text)
	if m == nil {
		return nil
	}
	sign := 1
	if m[1] == "-" {
		sign = -1
	}
	hh, _ := strconv.Atoi(m[2])
	mm, _ := strconv.Atoi(m[3])
	return time.FixedZone(text, sign*(hh*3600+mm*60))
}

// obsZones are the fixed zone abbreviations RFC 5322 §3.3 recognizes, with
// their offsets. Everything else a Date can name is either a numeric offset
// like -0700, an IANA name (parsed through time.LoadLocation), or a
// military single-letter zone, which the RFC says SHOULD NOT be used.
var obsZones = map[string]int{
	"EST": -5 * 3600, "EDT": -4 * 3600,
	"CST": -6 * 3600, "CDT": -5 * 3600,
	"MST": -7 * 3600, "MDT": -6 * 3600,
	"PST": -8 * 3600, "PDT": -7 * 3600,
	"UT": 0, "GMT": 0,
}

// ParseZone resolves a zone the way RFC 5322 §3.3 spells them: a numeric
// offset ("+0000", "-07:00"), one of the ten fixed obs-zone abbreviations
// ("PDT"), or an IANA name ("America/New_York") resolved through the tz
// database so DST is handled by the library. Military single-letter zones are
// refused, as the RFC's own recommendation implies. An empty string returns
// UTC.
func ParseZone(s string) (*time.Location, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.UTC, nil
	}
	if m := reZoneOffset.FindStringSubmatch(s); m != nil {
		return offsetZone(strings.ToUpper(m[1] + m[2] + m[3])), nil
	}
	upper := strings.ToUpper(s)
	if off, ok := obsZones[upper]; ok {
		return time.FixedZone(upper, off), nil
	}
	if loc, err := time.LoadLocation(s); err == nil {
		return loc, nil
	}
	// A single military letter is a plausible mistake worth naming in the
	// error; anything else is simply not a zone this knows.
	if len(s) == 1 && strings.ContainsAny(s, "ABCDEFGHIJKLMNOPQRSTUVWXYZ") {
		return nil, fmt.Errorf("zone %q: military single-letter zones are deprecated (RFC 5322 §3.3) and not supported", s)
	}
	return nil, fmt.Errorf("zone %q: not a numeric offset, obs-zone abbreviation, or IANA name", s)
}

// zoneAbbrev returns the abbreviation a zone goes by at t, when one is known:
// "PDT" under the fixed -0700 obs-zone, "EDT"/"EST" under an IANA zone.
// Empty when the zone has no abbreviation for t.
func zoneAbbrev(loc *time.Location, t time.Time) string {
	name, _ := t.In(loc).Zone()
	if name == "" {
		return ""
	}
	return name
}

// ---------- X-MSFBL ----------

// MSFBL is the decoded SparkPost X-MSFBL JSON payload.
type MSFBL struct {
	CustomerID string `json:"customer_id"`
	TenantID   string `json:"tenant_id"`
	MessageID  string `json:"message_id"`
	R          string `json:"r"`
	Subaccount string `json:"subaccount_id"`
}

// Epoch returns the Unix timestamp carried in the first 4 bytes (8 hex chars)
// of the Mongo-ObjectId-shaped message_id.
func (x *MSFBL) Epoch() (int64, error) {
	if len(x.MessageID) < 8 {
		return 0, fmt.Errorf("message_id %q too short for embedded timestamp", x.MessageID)
	}
	sec, err := strconv.ParseInt(x.MessageID[:8], 16, 64)
	if err != nil {
		return 0, fmt.Errorf("message_id %q: first 8 chars not hex timestamp", x.MessageID)
	}
	return sec, nil
}

// DecodeMSFBL finds, unfolds and decodes the X-MSFBL header.
func (m *Message) DecodeMSFBL() (*MSFBL, error) {
	h := m.Get("X-MSFBL")
	if h == "" {
		return nil, fmt.Errorf("no X-MSFBL header")
	}
	compact := stripAllWS(h)
	parts := strings.SplitN(compact, "|", 2)
	payload := parts[len(parts)-1]
	if pad := len(payload) % 4; pad != 0 {
		payload += strings.Repeat("=", 4-pad)
	}
	b, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		return nil, fmt.Errorf("X-MSFBL base64: %w", err)
	}
	var out MSFBL
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, fmt.Errorf("X-MSFBL json: %w", err)
	}
	return &out, nil
}

func stripAllWS(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch r {
		case ' ', '\t', '\n', '\r':
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// ---------- stamp extraction ----------

// Stamp is one timestamp found in the message.
type Stamp struct {
	Source  string // human-readable origin, e.g. "Date", "Received[2]", "X-MSFBL.message_id"
	Raw     string // raw text as found
	When    time.Time
	Seconds float64 // raw seconds/ms-derived value, for ms tails
	IsMS    bool
}

var (
	reMsgIDSeed = regexp.MustCompile(`<(\d{10,13})(\.\d+\.\d+@)`)
	reXRecvTail = regexp.MustCompile(`\.(\d{13})(;)`)
	reRecvDate  = regexp.MustCompile(`(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun),\s+\d{1,2}\s+[A-Za-z]{3}\s+\d{4}\s+\d{2}:\d{2}:\d{2}\s+[+-]\d{4}`)
	reMxDotted  = regexp.MustCompile(`\.(\d{4})\.(\d{2})\.(\d{2})\.(\d{2})\.(\d{2})\.(\d{2})`)
)

// Stamps extracts every timestamp-bearing value, in header order.
func (m *Message) Stamps() []Stamp {
	var out []Stamp
	if msfbl, err := m.DecodeMSFBL(); err == nil {
		if sec, err := msfbl.Epoch(); err == nil {
			out = append(out, Stamp{
				Source: "X-MSFBL.message_id",
				Raw:    msfbl.MessageID,
				When:   time.Unix(sec, 0).UTC(),
			})
		}
	}
	if d := m.Date(); !d.IsZero() {
		out = append(out, Stamp{Source: "Date", Raw: m.Get("Date"), When: d})
	}
	if mm := reMsgIDSeed.FindStringSubmatch(m.Get("Message-ID")); mm != nil {
		if n, err := strconv.ParseInt(mm[1], 10, 64); err == nil {
			out = append(out, Stamp{
				Source:  "Message-ID.seed",
				Raw:     mm[0],
				When:    time.Unix(n/100, 0).UTC(),
				Seconds: float64(n) / 100,
			})
		}
	}
	recvIdx := 0
	for _, h := range m.Headers {
		switch {
		case strings.EqualFold(h.Name, "Received"):
			recvIdx++
			if dm := reRecvDate.FindString(h.Value); dm != "" {
				if t, err := ParseRFC2822(dm); err == nil {
					out = append(out, Stamp{
						Source: fmt.Sprintf("Received[%d].date", recvIdx),
						Raw:    dm,
						When:   t,
					})
				}
			}
			if strings.Contains(h.Value, "mx.google.com") {
				if dm := reMxDotted.FindStringSubmatch(h.Value); dm != nil {
					// interpret in the offset of this header's own date line
					var off int
					if od := reRecvDate.FindString(h.Value); od != "" {
						if t, err := ParseRFC2822(od); err == nil {
							_, off = t.Zone()
						}
					}
					loc := time.FixedZone("recv", off)
					y, _ := strconv.Atoi(dm[1])
					mo, _ := strconv.Atoi(dm[2])
					dd, _ := strconv.Atoi(dm[3])
					hh, _ := strconv.Atoi(dm[4])
					mi, _ := strconv.Atoi(dm[5])
					ss, _ := strconv.Atoi(dm[6])
					t := time.Date(y, time.Month(mo), dd, hh, mi, ss, 0, loc)
					out = append(out, Stamp{
						Source: fmt.Sprintf("Received[%d].mxid", recvIdx),
						Raw:    dm[0][1:],
						When:   t,
					})
				}
			}
		case strings.EqualFold(h.Name, "X-Received"):
			if tm := reXRecvTail.FindStringSubmatch(h.Value); tm != nil {
				if n, err := strconv.ParseInt(tm[1], 10, 64); err == nil {
					out = append(out, Stamp{
						Source:  "X-Received.tail",
						Raw:     tm[1],
						When:    time.UnixMilli(n).UTC(),
						Seconds: float64(n) / 1000,
						IsMS:    true,
					})
				}
			}
		}
	}
	return out
}
