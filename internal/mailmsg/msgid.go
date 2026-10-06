package mailmsg

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// The Message-ID seed is the timestamp-bearing integer at the head of an
// Eventbrite/SparkPost Message-ID:
//
//	<178811367700.7.17946179276067562017@ip-172-21-223-177.ec2.internal>
//
// The leading integer is the send time in hundredths of a second since the
// Unix epoch; a process id and a random suffix follow. It is the only carrier
// of the send time that nothing else in the message restates, which makes it
// the one worth reading when the Date-bearing headers disagree.
//
// The width of the integer fixes its unit. Only the unambiguous widths are
// accepted: 10 digits are seconds, 12 centiseconds, 13 milliseconds. An
// 11-digit seed could be either scale, so ParseSeed rejects it rather than
// guessing and silently producing a send time decades off.

const (
	seedSecsDigits  = 10
	seedCentisDigit = 12
	seedMillisDigit = 13
)

var reSeedHead = regexp.MustCompile(`^<(\d+)\.`)

// Seed is the send time encoded in a Message-ID, kept in the tick unit the
// Message-ID was written with so that rewriting it preserves the original
// width and sub-second precision.
type Seed struct {
	width int   // digits the seed was written with
	ticks int64 // send time in units of 1/unit second
	unit  int64 // ticks per second
}

// ParseSeed parses the leading integer of a Message-ID value, inferring the
// unit from its width.
func ParseSeed(s string) (Seed, error) {
	u := ticksPerSecond(len(s))
	if u == 0 {
		return Seed{}, fmt.Errorf("seed %q: %d digits does not identify a unit (want 10, 12 or 13)", s, len(s))
	}
	ticks, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return Seed{}, fmt.Errorf("seed %q: %w", s, err)
	}
	return Seed{width: len(s), ticks: ticks, unit: u}, nil
}

func ticksPerSecond(digits int) int64 {
	switch digits {
	case seedSecsDigits:
		return 1
	case seedCentisDigit:
		return 100
	case seedMillisDigit:
		return 1000
	default:
		return 0
	}
}

// At returns the send time the seed encodes, including its sub-second part.
// A seed minted from an integer timestamp has a zero remainder; a live send
// almost never does.
func (s Seed) At() time.Time {
	return time.Unix(s.ticks/s.unit, (s.ticks%s.unit)*(int64(time.Second)/s.unit))
}

// Remainder returns the sub-second part of the seed, i.e. what a live send
// leaves behind and a regeneration from a whole-second timestamp does not.
func (s Seed) Remainder() time.Duration {
	return time.Duration(s.Fraction()) * (time.Second / time.Duration(s.unit))
}

// Shift returns the seed moved by d, rounded down to the seed's own unit. The
// original width is preserved so the rewritten Message-ID keeps the shape the
// MTA minted.
func (s Seed) Shift(d time.Duration) Seed {
	s.ticks += int64(d / (time.Second / time.Duration(s.unit)))
	return s
}

// Unit returns how many ticks the seed counts per second: 1 for a 10-digit
// seed, 100 for centiseconds, 1000 for milliseconds.
func (s Seed) Unit() int64 { return s.unit }

// Fraction returns the sub-second part as a count of the seed's own ticks.
func (s Seed) Fraction() int64 { return s.ticks - s.ticks/s.unit*s.unit }

// SetFraction replaces the sub-second part, keeping the whole seconds. It
// panics when frac falls outside [0, Unit()), which is a caller error rather
// than a condition worth carrying forward.
func (s Seed) SetFraction(frac int64) Seed {
	if frac < 0 || frac >= s.unit {
		panic(fmt.Sprintf("mailmsg: seed fraction %d outside [0,%d)", frac, s.unit))
	}
	s.ticks = s.ticks/s.unit*s.unit + frac
	return s
}

// String renders the seed as it was written.
func (s Seed) String() string {
	return fmt.Sprintf("%0*d", s.width, s.ticks)
}

// MessageIDSeed returns the Seed carried by the Message-ID header. ok is
// false when the message has no Message-ID or its head is not a seed.
func (m *Message) MessageIDSeed() (Seed, bool) {
	// Get keeps the leading space of a folded value, so trim it before
	// anchoring on the opening angle bracket.
	g := reSeedHead.FindStringSubmatch(strings.TrimSpace(m.Get("Message-ID")))
	if g == nil {
		return Seed{}, false
	}
	seed, err := ParseSeed(g[1])
	if err != nil {
		return Seed{}, false
	}
	return seed, true
}
