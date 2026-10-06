package mailmsg

import (
	"strconv"
	"testing"
	"time"
)

func TestParseSeedInfersUnitFromWidth(t *testing.T) {
	tests := []struct {
		seed    string
		want    time.Time
		remain  time.Duration
		wantErr bool
	}{
		{seed: "1788113677", want: time.Date(2026, 8, 30, 18, 14, 37, 0, time.UTC)},
		{seed: "178811367700", want: time.Date(2026, 8, 30, 18, 14, 37, 0, time.UTC)},
		{seed: "1788113677000", want: time.Date(2026, 8, 30, 18, 14, 37, 0, time.UTC)},
		{
			seed:   "178811367743",
			want:   time.Date(2026, 8, 30, 18, 14, 37, 430*int(time.Millisecond), time.UTC),
			remain: 430 * time.Millisecond,
		},
		{seed: "17881136770", wantErr: true}, // 11 digits: seconds or centis, unknowable
		{seed: "17881136770000", wantErr: true},
		{seed: "", wantErr: true},
	}
	for _, tc := range tests {
		got, err := ParseSeed(tc.seed)
		if tc.wantErr {
			if err == nil {
				t.Errorf("ParseSeed(%q) = %v, want error", tc.seed, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseSeed(%q): %v", tc.seed, err)
			continue
		}
		if !got.At().Equal(tc.want) {
			t.Errorf("ParseSeed(%q).At() = %v, want %v", tc.seed, got.At(), tc.want)
		}
		if got.Remainder() != tc.remain {
			t.Errorf("ParseSeed(%q).Remainder() = %v, want %v", tc.seed, got.Remainder(), tc.remain)
		}
	}
}

func TestSeedRoundTripsThroughString(t *testing.T) {
	for _, s := range []string{"1788113677", "178811367700", "1788113677000"} {
		seed, err := ParseSeed(s)
		if err != nil {
			t.Fatalf("ParseSeed(%q): %v", s, err)
		}
		if seed.String() != s {
			t.Errorf("ParseSeed(%q).String() = %q, want the input back", s, seed.String())
		}
	}
}

func TestSeedShiftPreservesWidthAndRemainder(t *testing.T) {
	seed, err := ParseSeed("178811367743")
	if err != nil {
		t.Fatal(err)
	}
	delta := time.Date(2026, 9, 16, 10, 0, 0, 0, time.UTC).
		Sub(time.Date(2026, 8, 30, 18, 14, 37, 0, time.UTC))

	got := seed.Shift(delta)
	if len(got.String()) != len("178811367743") {
		t.Errorf("Shift changed the seed width: %q", got.String())
	}
	if got.Remainder() != seed.Remainder() {
		t.Errorf("Shift changed the sub-second remainder: %v", got.Remainder())
	}
	want := time.Date(2026, 9, 16, 10, 0, 0, 430*int(time.Millisecond), time.UTC)
	if !got.At().Equal(want) {
		t.Errorf("Shift(...).At() = %v, want %v", got.At(), want)
	}
}

func TestSeedUnitAndFraction(t *testing.T) {
	tests := []struct {
		seed string
		unit int64
		frac int64
	}{
		{"1788113677", 1, 0},
		{"178811367700", 100, 0},
		{"178811367769", 100, 69},
		{"1788113677000", 1000, 0},
		{"1788113677430", 1000, 430},
	}
	for _, tc := range tests {
		seed, err := ParseSeed(tc.seed)
		if err != nil {
			t.Errorf("ParseSeed(%q): %v", tc.seed, err)
			continue
		}
		if seed.Unit() != tc.unit {
			t.Errorf("ParseSeed(%q).Unit() = %d, want %d", tc.seed, seed.Unit(), tc.unit)
		}
		if seed.Fraction() != tc.frac {
			t.Errorf("ParseSeed(%q).Fraction() = %d, want %d", tc.seed, seed.Fraction(), tc.frac)
		}
	}
}

func TestSeedSetFractionKeepsWholeSeconds(t *testing.T) {
	seed, err := ParseSeed("178811367700")
	if err != nil {
		t.Fatal(err)
	}
	got := seed.SetFraction(69)
	if got.String() != "178811367769" {
		t.Errorf("SetFraction(69).String() = %q, want %q", got.String(), "178811367769")
	}
	want := time.Date(2026, 8, 30, 18, 14, 37, 690*int(time.Millisecond), time.UTC)
	if !got.At().Equal(want) {
		t.Errorf("SetFraction(69).At() = %v, want %v", got.At(), want)
	}
	if got.Fraction() != 69 || got.Unit() != 100 {
		t.Errorf("SetFraction(69) changed the unit or fraction: unit=%d frac=%d", got.Unit(), got.Fraction())
	}
	if len(got.String()) != len(seed.String()) {
		t.Errorf("SetFraction changed the seed width: %q", got.String())
	}
}

func TestSeedSetFractionRejectsOutOfRange(t *testing.T) {
	for _, frac := range []int64{-1, 100, 1000} {
		t.Run(strconv.FormatInt(frac, 10), func(t *testing.T) {
			seed, err := ParseSeed("178811367700")
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if recover() == nil {
					t.Errorf("SetFraction(%d) on a 100-ticks-per-second seed did not panic", frac)
				}
			}()
			seed.SetFraction(frac)
		})
	}
}

func TestMessageIDSeedReadsFoldedHeader(t *testing.T) {
	raw := "Message-ID: \n" +
		" <178811367700.7.17946179276067562017@ip-172-21-223-177.ec2.internal>\n" +
		"Date: Sun, 30 Aug 2026 18:14:37 -0000\n" +
		"\n" +
		"body\n"
	m, err := Parse([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	seed, ok := m.MessageIDSeed()
	if !ok {
		t.Fatal("MessageIDSeed: not found in a folded Message-ID header")
	}
	if !seed.At().Equal(m.Date()) {
		t.Errorf("seed decodes to %v, Date header says %v", seed.At(), m.Date())
	}
}

func TestMessageIDSeedRejectsNonSeed(t *testing.T) {
	for _, v := range []string{
		"<abc@example.com>",
		"<17881136770.7.1@example.com>", // ambiguous width
		"<>",
	} {
		m, err := Parse([]byte("Message-ID: " + v + "\nDate: Sun, 30 Aug 2026 18:14:37 -0000\n\nb\n"))
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := m.MessageIDSeed(); ok {
			t.Errorf("MessageIDSeed accepted %q", v)
		}
	}
}
