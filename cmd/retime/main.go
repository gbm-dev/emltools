// Command retime calculates and rewrites the send-time metadata of an .eml.
//
// The X-MSFBL header carries a base64 JSON blob whose message_id is a Mongo
// ObjectId; its first 4 bytes are a big-endian Unix timestamp, i.e. the real
// time Eventbrite/SparkPost generated the message. retime analyze reports
// every derived timestamp, the drift between them, and the sub-second part of
// the Message-ID seed; retime retime moves the Date, Message-ID seed,
// X-Received ms tail, RFC 5322 dates and the mx.google dotted id by one uniform
// delta, and pins the two headers that record the injection directly, X-MSFBL
// and the ecelerity queue ID, to the target, so the rewritten message has no
// carrier left behind at the old send time.
//
// The queue ID is the MTA's own record of the injection, shaped
// "<queue>/<sub>-<job>-<TIME>"; its trailing 8 hex are the Unix time with the
// digits reversed, so the time is recoverable from the ID alone and no
// external state is needed to move it. Pinning rather than shifting is what
// lets a retime repair a message whose Date was already moved: on such a
// message the shift would be zero, leaving the injection time in the one
// header the Date-derived carriers do not override.
//
// The Message-ID seed is shifted in the unit its width implies (10 digits are
// seconds, 12 centiseconds, 13 milliseconds); a seed of ambiguous width is
// refused rather than moved at the wrong scale.
//
// A sub-second-capable carrier that would land on an exact whole second is
// seeded with a stable non-zero sub-second part instead. A whole second is what
// regenerating a timestamp from an integer leaves behind, and a live send
// almost never does, so carrying one through would leave the retimed message
// marked as a regeneration.
//
// A rewritten date keeps the shape it was written with: the day's padding, the
// zone spelled the way the original spelled it, and any trailing zone comment.
// Re-rendering a date from its parsed time would drop all three, and the "+0000"
// it writes in place of the sender's "-0000" is a claim about the sender's zone
// that RFC 5322 does not permit it to make.
package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"hash/fnv"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"gbm.dev/emltools/internal/mailmsg"
)

var (
	reRFC2822  = regexp.MustCompile(`(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun), \d{1,2} [A-Za-z]{3} \d{4} \d{2}:\d{2}:\d{2} [+-]\d{4}(?: \([A-Z]{3}\))?`)
	reDotted   = regexp.MustCompile(`\.(\d{4})\.(\d{2})\.(\d{2})\.(\d{2})\.(\d{2})\.(\d{2})([\s;]|$)`)
	reDateHdr  = regexp.MustCompile(`(?m)^Date:[ \t]*([^\n]*(\n[ \t][^\n]*)*)`)
	reMSFBLHdr = regexp.MustCompile(`(?m)^X-MSFBL:[ \t]*([^\r\n]*(\r?\n[ \t]+[^\r\n]*)*)`)

	// reUnixMs captures the millisecond receipt time at the end of a Gmail
	// X-Received id, along with the id token it hangs off. That token identifies
	// the delivery and does not move with the send time, so it is what a seeded
	// sub-second part has to be keyed on for a rerun to derive the same value.
	reUnixMs = regexp.MustCompile(`([^\s;]*\.)(\d{13})(;)`)

	// reMsgID captures a Message-ID seed and the pid/random suffix after it.
	// The width is capped at 13 so that a seed of unknown unit is refused
	// rather than shifted at the wrong scale.
	reMsgID = regexp.MustCompile(`<(\d{10,13})(\.\d+\.\d+@)`)

	// reQueueID captures an ecelerity (Momentum) queue ID: the SparkPost MTA's
	// own record of the injection, shaped "<queue>/<sub>-<job>-<TIME>". The
	// leading fields are specific enough that Gmail's own "with SMTP id
	// <token>;" never matches, and the trailing semicolon is required so the
	// match cannot run past the end of the ID.
	reQueueID = regexp.MustCompile(`(\bid [0-9A-F]{2}/[0-9A-F]{2}-[0-9]+-)([0-9A-F]{8})(;)`)
)

// minRelayEpoch is the earliest injection time a queue ID's time field can
// plausibly carry, 2012-07-13. Below it the trailing 8 hex are not a reversed
// Unix time and shifting them would corrupt an ID that merely resembles one.
const minRelayEpoch = 0x50000000

// queueEpoch decodes the injection time from the trailing 8 hex of an
// ecelerity queue ID. Those digits are the Unix time with the hex digits
// reversed: "945CAAA6" is 6AAAC549, and that relay's own Received line reads
// 2026-09-16 16:35:21 +0000 to the second.
//
// ok is false when the value is not a plausible time. The caller then leaves
// the field alone, because an ID that merely resembles a queue ID carries no
// time to move.
func queueEpoch(field string) (int64, bool) {
	d := []byte(field)
	for i, j := 0, len(d)-1; i < j; i, j = i+1, j-1 {
		d[i], d[j] = d[j], d[i]
	}
	v, err := strconv.ParseUint(string(d), 16, 32)
	if err != nil || v < minRelayEpoch {
		return 0, false
	}
	return int64(v), true
}

// formatQueueEpoch renders an injection time back into the reversed digit
// order the MTA mints, so the rewritten ID keeps its original shape.
func formatQueueEpoch(epoch int64) string {
	d := []byte(fmt.Sprintf("%08X", uint32(epoch)))
	for i, j := 0, len(d)-1; i < j; i, j = i+1, j-1 {
		d[i], d[j] = d[j], d[i]
	}
	return string(d)
}

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	switch os.Args[1] {
	case "analyze":
		flags, rest := partition(os.Args[2:])
		fs := flag.NewFlagSet("analyze", flag.ExitOnError)
		fs.Parse(flags)
		if len(rest) != 1 {
			usage()
		}
		raw := read(rest[0])
		report(raw)
	case "retime", "msfbl", "sparkpost":
		flags, rest := partition(os.Args[2:])
		fs := flag.NewFlagSet(os.Args[1], flag.ExitOnError)
		out := fs.String("o", "", "output path (default: <eml>.retimed.eml)")
		set := fs.String("set", "", `target time, e.g. "2026-08-30 14:14:37 -0400" (default: X-MSFBL or Date header)`)
		zone := fs.String("zone", "", `zone the Date header is written in: offset ("-0700"), obs-zone ("PDT"), or IANA name ("America/Los_Angeles") (default: keep each header's own zone)`)
		msfblFlag := fs.Bool("msfbl", false, "retime the SparkPost X-MSFBL header to match Date (or --set)")
		sparkpostFlag := fs.Bool("sparkpost", false, "alias for --msfbl")
		fs.Parse(flags)
		if len(rest) != 1 {
			usage()
		}
		path := rest[0]
		raw := read(path)

		z, err := mailmsg.ParseZone(*zone)
		if err != nil {
			fatal(err)
		}
		isMSFBL := os.Args[1] == "msfbl" || os.Args[1] == "sparkpost" || *msfblFlag || *sparkpostFlag
		var retimed string
		if isMSFBL {
			retimed, err = retimeMSFBL(raw, *set)
		} else {
			retimed, err = retime(raw, *set, z)
		}
		if err != nil {
			fatal(err)
		}
		dst := *out
		if dst == "" {
			dst = path + ".retimed.eml"
		}
		if err := os.WriteFile(dst, []byte(retimed), 0o644); err != nil {
			fatal(err)
		}
		fmt.Printf("wrote %s\n", dst)
		report(retimed)
	default:
		usage()
	}
}

// partition splits args into flag arguments and positionals, tolerating flags
// placed after positional arguments (Go's flag package stops at the first
// non-flag argument). Flags are value-taking unless listed as boolean.
func partition(args []string) (flags, rest []string) {
	boolean := map[string]bool{
		"-json": true, "--json": true,
		"-no-dns": true, "--no-dns": true,
		"-arc": true, "--arc": true,
		"-help": true, "--help": true, "-h": true,
		"-msfbl": true, "--msfbl": true,
		"-sparkpost": true, "--sparkpost": true,
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

func usage() {
	fmt.Fprintln(os.Stderr, `usage: retime analyze <file.eml>
       retime retime <file.eml> [-o out.eml] [--set "YYYY-MM-DD HH:MM:SS ±HHMM"] [--zone Z] [--msfbl|--sparkpost]
       retime sparkpost <file.eml> [-o out.eml] [--set "YYYY-MM-DD HH:MM:SS ±HHMM"]
       retime msfbl <file.eml> [-o out.eml] [--set "YYYY-MM-DD HH:MM:SS ±HHMM"]`)
	os.Exit(2)
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "retime:", err)
	os.Exit(1)
}

func read(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		fatal(err)
	}
	return string(b)
}

func splitHeaders(raw string) (string, string) {
	if i := strings.Index(raw, "\n\n"); i >= 0 {
		return raw[:i+1], raw[i+1:]
	}
	return raw, ""
}

func msfblEpoch(headers string) (int64, error) {
	m, err := mailmsg.Parse([]byte(headers + "\n\n"))
	if err != nil {
		return 0, err
	}
	x, err := m.DecodeMSFBL()
	if err != nil {
		return 0, err
	}
	return x.Epoch()
}

func dateHeader(headers string) (time.Time, error) {
	m, err := mailmsg.Parse([]byte(headers + "\n\n"))
	if err != nil {
		return time.Time{}, err
	}
	d := m.Date()
	if d.IsZero() {
		return time.Time{}, fmt.Errorf("no Date header found")
	}
	return d, nil
}

func parseTarget(headers, setFlag string) (time.Time, error) {
	if setFlag != "" {
		if t, err := time.Parse("2006-01-02 15:04:05 -0700", setFlag); err == nil {
			return t, nil
		}
		if t, err := mailmsg.ParseRFC2822(setFlag); err == nil {
			return t, nil
		}
		return time.Time{}, fmt.Errorf("--set: invalid time format (expected 'YYYY-MM-DD HH:MM:SS ±HHMM' or RFC2822)")
	}
	return dateHeader(headers)
}

func stripWS(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r != ' ' && r != '\t' && r != '\n' && r != '\r' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// rewriteMSFBL sets the Unix epoch embedded in the X-MSFBL ObjectId to target,
// carrying the base64 prefix through byte for byte. moved reports whether the
// header was present; headers without one come back untouched.
func rewriteMSFBL(headers string, target time.Time) (out string, moved bool, err error) {
	loc := reMSFBLHdr.FindStringSubmatchIndex(headers)
	if loc == nil {
		return headers, false, nil
	}

	headerText := headers[loc[0]:loc[1]]
	colonIdx := strings.Index(headerText, ":")
	if colonIdx == -1 {
		return "", false, fmt.Errorf("malformed X-MSFBL header")
	}
	val := stripWS(headerText[colonIdx+1:])
	parts := strings.SplitN(val, "|", 2)
	if len(parts) != 2 {
		return "", false, fmt.Errorf("malformed X-MSFBL header value: missing '|'")
	}
	prefix := parts[0]
	payload := parts[1]
	if pad := len(payload) % 4; pad != 0 {
		payload += strings.Repeat("=", 4-pad)
	}
	b, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		return "", false, fmt.Errorf("decode X-MSFBL base64: %w", err)
	}

	reHexTimestamp := regexp.MustCompile(`("message_id"\s*:\s*")([0-9a-fA-F]{8})([0-9a-fA-F]*)(")`)
	if !reHexTimestamp.Match(b) {
		return "", false, fmt.Errorf("message_id in X-MSFBL json does not match expected hex format")
	}

	newEpochHex := fmt.Sprintf("%08x", target.UTC().Unix())
	newJSON := reHexTimestamp.ReplaceAll(b, []byte("${1}"+newEpochHex+"${3}${4}"))

	newHeader := fmt.Sprintf("X-MSFBL: %s|%s", prefix, base64.StdEncoding.EncodeToString(newJSON))
	return headers[:loc[0]] + newHeader + headers[loc[1]:], true, nil
}

// seededFraction derives a stable non-zero sub-second part from key, counted in
// the caller's own ticks per second.
//
// A carrier that lands on an exact whole second reproduces the signature of a
// timestamp regenerated from an integer rather than minted by a clock, because
// a live send leaves jitter behind. So a whole second is replaced with a value
// drawn from the message's own invariant text: keying on something the retime
// does not move keeps a rerun byte-identical, and excluding zero keeps the
// seeded value from being a whole second in its own right.
func seededFraction(key string, unit int64) int64 {
	if unit < 2 {
		panic(fmt.Sprintf("seededFraction: unit %d leaves no sub-second space", unit))
	}
	h := fnv.New64a()
	io.WriteString(h, key)
	return 1 + int64(h.Sum64()%uint64(unit-1))
}

// retimeMSFBL rewrites the embedded Unix timestamp in the SparkPost X-MSFBL
// header to match target (defaulting to the Date header), leaving every other
// carrier where it was.
func retimeMSFBL(raw, setFlag string) (string, error) {
	headers, body := splitHeaders(raw)
	target, err := parseTarget(headers, setFlag)
	if err != nil {
		return "", err
	}
	headers, moved, err := rewriteMSFBL(headers, target)
	if err != nil {
		return "", err
	}
	if !moved {
		return "", fmt.Errorf("no X-MSFBL header found")
	}
	return headers + body, nil
}

// retime shifts every derived timestamp by target-original. The Date header is
// rendered in zone when one is named; every other date keeps the zone its own
// system wrote.
func retime(raw, setFlag string, zone *time.Location) (string, error) {
	headers, body := splitHeaders(raw)
	if setFlag != "" {
		t, err := parseTarget(headers, setFlag)
		if err != nil {
			return "", err
		}
		return apply(headers, body, t, zone)
	}
	epoch, err := msfblEpoch(headers)
	if err != nil {
		return "", err
	}
	return apply(headers, body, time.Unix(epoch, 0).UTC(), zone)
}

func apply(headers, body string, target time.Time, zone *time.Location) (string, error) {
	original, err := dateHeader(headers)
	if err != nil {
		return "", err
	}
	delta := target.Sub(original)
	secs := int64(delta.Seconds())

	// A date is re-rendered in the shape it already had, so the pass leaves the
	// header looking like the mail system wrote it rather than like this tool
	// did. At delta zero it is skipped outright, which keeps a message that is
	// already at the target byte-identical whatever shape its dates are in.
	shiftRFC := func(s string) string {
		if delta == 0 {
			return s
		}
		t, err := mailmsg.ParseRFC2822(s)
		if err != nil {
			return s
		}
		return mailmsg.FormatRFC2822Like(t.Add(delta), s)
	}
	headers = reRFC2822.ReplaceAllStringFunc(headers, shiftRFC)

	headers = reDotted.ReplaceAllStringFunc(headers, func(s string) string {
		m := reDotted.FindStringSubmatch(s)
		y, _ := strconv.Atoi(m[1])
		mo, _ := strconv.Atoi(m[2])
		dd, _ := strconv.Atoi(m[3])
		hh, _ := strconv.Atoi(m[4])
		mi, _ := strconv.Atoi(m[5])
		ss, _ := strconv.Atoi(m[6])
		nd := time.Date(y, time.Month(mo), dd, hh, mi, ss, 0, time.UTC).Add(delta)
		return fmt.Sprintf(".%04d.%02d.%02d.%02d.%02d.%02d%s",
			nd.Year(), nd.Month(), nd.Day(), nd.Hour(), nd.Minute(), nd.Second(), m[7])
	})

	// The seed's unit follows from its width. Refuse a width that does not
	// identify one rather than shifting it at the wrong scale and writing a
	// send time decades off.
	for _, m := range reMsgID.FindAllStringSubmatch(headers, -1) {
		if _, err := mailmsg.ParseSeed(m[1]); err != nil {
			return "", err
		}
	}
	headers = reMsgID.ReplaceAllStringFunc(headers, func(s string) string {
		m := reMsgID.FindStringSubmatch(s)
		seed, _ := mailmsg.ParseSeed(m[1])
		seed = seed.Shift(delta)

		// A 10-digit seed counts whole seconds and has no sub-second field to
		// seed, so only a finer unit can carry one.
		if seed.Unit() > 1 && seed.Fraction() == 0 {
			seed = seed.SetFraction(seededFraction(m[2], seed.Unit()))
		}
		return "<" + seed.String() + m[2]
	})

	// The seed and the receipt time are drawn independently because they
	// timestamp different events: the send, and Gmail's receipt of it. In
	// principle two independent draws could put the receipt before the send if
	// both fell in the same second; in every message on hand the receipt is a
	// whole second later, so the ordering holds without constraining the draw.
	// Reopen if a message turns up whose seed and receipt share a whole second
	// with both sub-second parts zero.
	headers = reUnixMs.ReplaceAllStringFunc(headers, func(s string) string {
		m := reUnixMs.FindStringSubmatch(s)
		n, _ := strconv.ParseInt(m[2], 10, 64)
		n += secs * 1000
		if n%1000 == 0 {
			n += seededFraction(m[1], 1000)
		}
		return m[1] + strconv.FormatInt(n, 10) + m[3]
	})

	// The relay's queue ID restates the injection time in its trailing 8 hex,
	// reversed. No stage of the pipeline recomputes it, so leaving it alone
	// leaves the original send time readable in the header.
	//
	// It is pinned to the target rather than shifted by target-minus-Date, the
	// same treatment X-MSFBL gets, because it records the injection directly
	// instead of deriving from Date. On an honest message the two are
	// indistinguishable: the MTA writes the queue ID and the Date at the same
	// instant, so shifting moves the relay by exactly the distance to the
	// target. On a message whose Date has already moved they diverge, and only
	// pinning repairs it, because the shift would be the distance between that
	// message's Date and the target, which is zero.
	//
	// It counts whole seconds, so the pinned value is the target truncated to a
	// second.
	//
	// Deliberate skip: a message relayed through two Momentum MTAs carries two
	// queue IDs whose times differ by the relay's latency, and pinning both
	// collapses that gap. No message on hand carries more than one, and the gap
	// it would erase is seconds of relay delay rather than a send time. Reopen
	// when a message turns up with two ecelerity queue IDs, or when a queue ID
	// turns up whose time is not the injection time of the Received line it
	// sits on.
	pinnedEpoch := target.UTC().Unix()
	headers = reQueueID.ReplaceAllStringFunc(headers, func(s string) string {
		m := reQueueID.FindStringSubmatch(s)
		if _, ok := queueEpoch(m[2]); !ok {
			return s
		}
		return m[1] + formatQueueEpoch(pinnedEpoch) + m[3]
	})

	// The Date header is restated from the target rather than shifted, so it
	// reads the target instant even when the original's offset text renders that
	// instant at a different wall time. It keeps the original's shape, since the
	// offset text and the day's padding are the header's, not this tool's; the
	// value is unfolded first so a folded Date still parses. A --zone overrides
	// that: the Date is the one header that claims the sender's zone, so it is
	// the one header a zone change rewrites. Received lines keep the zones their
	// own MTAs wrote, and the instant-valued carriers (X-MSFBL, queue ID, seed)
	// carry no zone at all.
	headers = reDateHdr.ReplaceAllStringFunc(headers, func(s string) string {
		value := strings.Join(strings.Fields(reDateHdr.FindStringSubmatch(s)[1]), " ")
		return "Date: " + mailmsg.FormatRFC2822LikeIn(target, value, zone)
	})
	// X-MSFBL carries the ObjectId the other carriers are measured against, so
	// leaving it at the old send time would manufacture exactly the drift a
	// retime exists to remove.
	if headers, _, err = rewriteMSFBL(headers, target); err != nil {
		return "", err
	}
	return headers + body, nil
}

func report(raw string) {
	headers, _ := splitHeaders(raw)
	m, err := mailmsg.Parse([]byte(headers + "\n\n"))
	if err != nil {
		fatal(err)
	}
	x, err := m.DecodeMSFBL()
	if err != nil {
		fmt.Fprintln(os.Stderr, "retime:", err)
		os.Exit(1)
	}
	epoch, _ := x.Epoch()
	msfblT := time.Unix(epoch, 0).UTC()
	dateT := m.Date()
	fmt.Printf("X-MSFBL message_id : %s\n", x.MessageID)
	fmt.Printf("X-MSFBL timestamp  : %s\n", msfblT.Format("2006-01-02 15:04:05 MST"))
	fmt.Printf("Date header        : %s\n", dateT.UTC().Format("2006-01-02 15:04:05 MST"))
	fmt.Printf("drift (msfbl-date) : %s\n", fmtDuration(msfblT.Sub(dateT)))
	if seed, ok := m.MessageIDSeed(); ok {
		fmt.Printf("Message-ID seed    : %s\n", seed.At().UTC().Format("2006-01-02 15:04:05 MST"))
		fmt.Printf("Message-ID sub-sec : %s\n", seedRemainderNote(seed))
	}
	for _, s := range m.Stamps() {
		switch s.Source {
		case "X-Received.tail":
			fmt.Printf("X-Received tail    : %s\n", s.When.Format("2006-01-02 15:04:05 MST"))
		case "Received[1].mxid", "Received[2].mxid", "Received[3].mxid", "Received[4].mxid", "Received[5].mxid":
			fmt.Printf("mx.google id       : %s\n", s.Raw)
		}
	}
}

// seedRemainderNote renders the sub-second part of a Message-ID seed. A seed
// minted by a live send almost always leaves one; a seed regenerated from a
// whole-second timestamp is exactly zero, which is the cheapest tell that the
// Message-ID was rewritten rather than minted.
func seedRemainderNote(seed mailmsg.Seed) string {
	if r := seed.Remainder(); r != 0 {
		return r.String()
	}
	return "0s (whole second: consistent with regeneration, not a live send)"
}

func fmtDuration(d time.Duration) string {
	if d < 0 {
		d = -d
	}
	days := int64(d.Hours()) / 24
	hours := int64(d.Hours()) % 24
	mins := int64(d.Minutes()) % 60
	secs := int64(d.Seconds()) % 60
	if days > 0 {
		return fmt.Sprintf("%dd%dh%dm%ds", days, hours, mins, secs)
	}
	return fmt.Sprintf("%dh%dm%ds", hours, mins, secs)
}
