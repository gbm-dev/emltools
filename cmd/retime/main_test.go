package main

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"gbm.dev/emltools/internal/mailmsg"
)

// msfblFixture is a real SparkPost X-MSFBL header: base64 prefix, a pipe, then
// the base64 JSON whose message_id is a Mongo ObjectId.
const msfblFixture = "X-MSFBL: pIbxEz3rgbbjXS/pvEccXSJ9/KNzvfid/vRn8TiHOdk=" +
	"|eyJyIjoiZ2FiZUBnYm0uZGV2IiwiY3VzdG9tZXJfaWQiOiIyNzQ2ODkiLCJtZXNzYWdlX2lkIjoiNmFhYWM1NDlhYTZhMjcxNjFhODkiLCJ0ZW5hbnRfaWQiOiJzcGMiLCJzdWJhY2NvdW50X2lkIjoiMTIifQ==\n"

// sourceSend is the send date the source message carries, 16 Sep 2026 16:35:21
// UTC. Its Date header and its Message-ID seed agree on the second, and the
// seed's 690 ms sub-second part says the Message-ID was minted by a live send.
const sourceSend = "2026-09-16 16:35:21 +0000"

// sourceSeed is the Message-ID seed the source message carries, in centiseconds.
const sourceSeed = "178957652169"

// retimeTargets are the send dates the pipeline forges toward, read off the two
// delivered messages: the order confirmation and the cancellation.
var retimeTargets = []string{
	"2026-08-30 18:14:37 +0000",
	"2026-09-03 16:35:21 +0000",
}

// fixture is a message carrying every send-time carrier retime knows about, at
// the source send date: the X-MSFBL ObjectId, the Date header, a folded
// Message-ID whose seed is the send time in centiseconds, a Received date and a
// folded X-Received whose id ends in Gmail's millisecond receipt time, and the
// ecelerity queue ID the relay minted at injection.
func fixture() string {
	return msfblFixture +
		"Date: Wed, 16 Sep 2026 16:35:21 -0000\n" +
		"Message-ID: \n" +
		" <" + sourceSeed + ".7.4788537881896003629@ip-172-21-213-153.ec2.internal>\n" +
		"Received: from [52.202.1.10] ([52.202.1.10:14250] helo=ip-172-21-213-153.ec2.internal)\n" +
		" by i-0bcf48c53d19b440e.mta1vsmtp.sd.prd.sparkpost (envelope-from <bounces@bounce.eventbrite.com>)\n" +
		" (ecelerity 5.3.0.76417 r(msys-ecelerity:tags/5.3.0.14)) with ESMTPSA (cipher=AES-256-GCM)\n" +
		" id 98/A9-06036-945CAAA6; Wed, 16 Sep 2026 16:35:21 +0000\n" +
		"Received: by 2002:a05:612c:2c01 with SMTP id ir1csp2824626vqb; Wed, 16 Sep 2026 09:35:23 -0700 (PDT)\n" +
		"X-Received: by 2002:a05:6a20:94ca:b0:3d3:b00b:26e8 with SMTP id\n" +
		" adf61e73a8af0-3dd5f8123f7mr8071326637.28.1789576522973;\n" +
		"       Wed, 16 Sep 2026 09:35:22 -0700 (PDT)\n" +
		"\n" +
		"Test message body\n"
}

func TestPartition(t *testing.T) {
	args := []string{"msg.eml", "-o", "out.eml", "--json", "extra"}
	flags, rest := partition(args)
	if len(rest) != 2 || rest[0] != "msg.eml" || rest[1] != "extra" {
		t.Fatalf("unexpected rest: %v", rest)
	}
	if len(flags) != 3 || flags[0] != "-o" || flags[1] != "out.eml" || flags[2] != "--json" {
		t.Fatalf("unexpected flags: %v", flags)
	}
}

func TestSplitHeaders(t *testing.T) {
	raw := "Header1: val1\nHeader2: val2\n\nBody line\n"
	h, b := splitHeaders(raw)
	if h != "Header1: val1\nHeader2: val2\n" {
		t.Errorf("unexpected headers: %q", h)
	}
	if b != "\nBody line\n" {
		t.Errorf("unexpected body: %q", b)
	}

	noBody := "Header1: val1\n"
	h2, b2 := splitHeaders(noBody)
	if h2 != noBody || b2 != "" {
		t.Errorf("unexpected noBody split: %q, %q", h2, b2)
	}
}

func TestFmtDuration(t *testing.T) {
	tests := []struct {
		d    time.Duration
		want string
	}{
		{0, "0h0m0s"},
		{time.Hour + 2*time.Minute + 3*time.Second, "1h2m3s"},
		{-(time.Hour + 2*time.Minute + 3*time.Second), "1h2m3s"},
		{25*time.Hour + 2*time.Minute, "1d1h2m0s"},
	}
	for _, tc := range tests {
		got := fmtDuration(tc.d)
		if got != tc.want {
			t.Errorf("fmtDuration(%v) = %q, want %q", tc.d, got, tc.want)
		}
	}
}

func TestRetimeWithSet(t *testing.T) {
	msg := "Date: Mon, 14 Sep 2026 10:00:00 +0000\n" +
		"Message-ID: <178942713900.123.456@example.com>\n" +
		"Received: by 2002:a05:123 with SMTP id abc; Mon, 14 Sep 2026 10:00:01 +0000\n" +
		"\n" +
		"Hello world\n"

	// Retime forward by 2 hours
	target := "2026-09-14 12:00:00 +0000"
	retimed, err := retime(msg, target, nil)
	if err != nil {
		t.Fatalf("retime failed: %v", err)
	}

	if !strings.Contains(retimed, "Date: Mon, 14 Sep 2026 12:00:00 +0000") {
		t.Errorf("Date header was not shifted correctly:\n%s", retimed)
	}
	if !strings.Contains(retimed, "Mon, 14 Sep 2026 12:00:01 +0000") {
		t.Errorf("Received date was not shifted correctly:\n%s", retimed)
	}
	if !strings.Contains(retimed, "Hello world\n") {
		t.Errorf("Body was not preserved:\n%s", retimed)
	}
}

func TestRetimeWithSparkPostHeader(t *testing.T) {
	msg := "X-MSFBL: q67CIa8d6uX0HMKB8fIRewsUC/K6r7hlUEoFXMFQSQg=|eyJjdXN0b21lcl9pZCI6IjI3NDY4OSIsInRlbmFudF9pZCI6InNwYyIsIm1lc3NhZ2VfaWQiOiI2YWE4N2RjM2FhNmE3NmI2NTZhNSIsInIiOiJuZWxzb25wZXJlejY5MDZAZ21haWwuY29tIiwic3ViYWNjb3VudF9pZCI6IjEyIn0=\n" +
		"Date: Sun, 30 Aug 2026 18:14:37 -0000\n" +
		"Message-ID: <178811367700.7.17946179276067562017@ip-172-21-223-177.ec2.internal>\n" +
		"Received: by 2002:a05:612c:2c01:b0:60c:47fe:eca0 with SMTP id ir1csp2814210vqb; Sun, 30 Aug 2026 11:14:38 -0700 (PDT)\n" +
		"\n" +
		"Test message body\n"

	retimed, err := retime(msg, "", nil)
	if err != nil {
		t.Fatalf("retime failed: %v", err)
	}

	// The source wrote "-0000", which asserts nothing about the sender's zone, so
	// the retimed Date keeps that spelling rather than promoting it to the
	// "+0000" that asserts UTC. The instant is the X-MSFBL timestamp either way.
	if !strings.Contains(retimed, "Date: Mon, 14 Sep 2026 23:05:39 -0000") {
		t.Errorf("Date header was not shifted to X-MSFBL timestamp:\n%s", retimed)
	}
	if !strings.Contains(retimed, "Mon, 14 Sep 2026 16:05:40 -0700") {
		t.Errorf("Received date was not shifted correctly:\n%s", retimed)
	}
	// The source's seed is a whole second, so the retimed one is seeded rather
	// than left ending in 00. What must hold is that it reads back at the target.
	m, err := mailmsg.Parse([]byte(retimed))
	if err != nil {
		t.Fatal(err)
	}
	seed, ok := m.MessageIDSeed()
	if !ok {
		t.Fatalf("no Message-ID seed after retime:\n%s", retimed)
	}
	wantSeed := time.Date(2026, 9, 14, 23, 5, 39, 0, time.UTC)
	if got := seed.At().Truncate(time.Second); !got.Equal(wantSeed) {
		t.Errorf("Message-ID seed reads back as %v, want %v", got, wantSeed)
	}
	if !strings.Contains(retimed, "Test message body\n") {
		t.Errorf("Body was not preserved:\n%s", retimed)
	}
}

func TestRetimeMSFBL(t *testing.T) {
	msg := "X-MSFBL: q67CIa8d6uX0HMKB8fIRewsUC/K6r7hlUEoFXMFQSQg=|eyJjdXN0b21lcl9pZCI6IjI3NDY4OSIsInRlbmFudF9pZCI6InNwYyIsIm1lc3NhZ2VfaWQiOiI2YWE4N2RjM2FhNmE3NmI2NTZhNSIsInIiOiJuZWxzb25wZXJlejY5MDZAZ21haWwuY29tIiwic3ViYWNjb3VudF9pZCI6IjEyIn0=\n" +
		"Date: Sun, 30 Aug 2026 18:14:37 -0000\n" +
		"Message-ID: <178811367700.7.17946179276067562017@ip-172-21-223-177.ec2.internal>\n" +
		"Received: by 2002:a05:612c:2c01:b0:60c:47fe:eca0 with SMTP id ir1csp2814210vqb; Sun, 30 Aug 2026 11:14:38 -0700 (PDT)\n" +
		"\n" +
		"Test message body\n"

	retimed, err := retimeMSFBL(msg, "")
	if err != nil {
		t.Fatalf("retimeMSFBL failed: %v", err)
	}

	headers, body := splitHeaders(retimed)
	epoch, err := msfblEpoch(headers)
	if err != nil {
		t.Fatalf("msfblEpoch failed: %v", err)
	}
	expectedEpoch := time.Date(2026, 8, 30, 18, 14, 37, 0, time.UTC).Unix()
	if epoch != expectedEpoch {
		t.Errorf("msfblEpoch = %d, want %d", epoch, expectedEpoch)
	}

	if !strings.Contains(retimed, "Date: Sun, 30 Aug 2026 18:14:37 -0000") {
		t.Errorf("Date header was unintentionally modified:\n%s", retimed)
	}
	if !strings.Contains(body, "Test message body\n") {
		t.Errorf("Body was not preserved:\n%s", retimed)
	}
}

func TestRetimeMSFBLWithSet(t *testing.T) {
	msg := "X-MSFBL: q67CIa8d6uX0HMKB8fIRewsUC/K6r7hlUEoFXMFQSQg=|eyJjdXN0b21lcl9pZCI6IjI3NDY4OSIsInRlbmFudF9pZCI6InNwYyIsIm1lc3NhZ2VfaWQiOiI2YWE4N2RjM2FhNmE3NmI2NTZhNSIsInIiOiJuZWxzb25wZXJlejY5MDZAZ21haWwuY29tIiwic3ViYWNjb3VudF9pZCI6IjEyIn0=\n" +
		"Date: Sun, 30 Aug 2026 18:14:37 -0000\n" +
		"\n" +
		"Test message body\n"

	retimed, err := retimeMSFBL(msg, "2026-09-03 16:35:21 +0000")
	if err != nil {
		t.Fatalf("retimeMSFBL with set failed: %v", err)
	}

	headers, _ := splitHeaders(retimed)
	epoch, err := msfblEpoch(headers)
	if err != nil {
		t.Fatalf("msfblEpoch failed: %v", err)
	}
	expectedEpoch := time.Date(2026, 9, 3, 16, 35, 21, 0, time.UTC).Unix()
	if epoch != expectedEpoch {
		t.Errorf("msfblEpoch = %d, want %d", epoch, expectedEpoch)
	}
}

// TestReflectSendDateInMessageID is the capability under test: retime takes a
// send date and writes it into every carrier the Message-ID carries, and
// reading those carriers back returns the send date that went in.
func TestReflectSendDateInMessageID(t *testing.T) {
	src, err := mailmsg.Parse([]byte(fixture()))
	if err != nil {
		t.Fatal(err)
	}
	srcSeed, ok := src.MessageIDSeed()
	if !ok {
		t.Fatal("fixture carries no Message-ID seed")
	}

	wants := append([]string{}, retimeTargets...)
	wants = append(wants, sourceSend) // identity: the date the source already carries

	for _, want := range wants {
		t.Run(want, func(t *testing.T) {
			target, err := parseTarget("", want)
			if err != nil {
				t.Fatal(err)
			}
			out, err := retime(fixture(), want, nil)
			if err != nil {
				t.Fatalf("retime: %v", err)
			}
			m, err := mailmsg.Parse([]byte(out))
			if err != nil {
				t.Fatal(err)
			}

			seed, ok := m.MessageIDSeed()
			if !ok {
				t.Fatalf("retimed message has no Message-ID seed:\n%s", out)
			}
			if got := seed.At().Truncate(time.Second); !got.Equal(target) {
				t.Errorf("Message-ID seed reads back as %v, want %v", got, target)
			}
			if seed.Remainder() != srcSeed.Remainder() {
				t.Errorf("sub-second part = %v, want the source's %v", seed.Remainder(), srcSeed.Remainder())
			}
			if got, want := len(seed.String()), len(srcSeed.String()); got != want {
				t.Errorf("seed width = %d digits, want %d: the unit changed under it", got, want)
			}

			epoch, err := msfblEpoch(mustHeaders(t, out))
			if err != nil {
				t.Fatalf("X-MSFBL after retime: %v", err)
			}
			if got := time.Unix(epoch, 0).UTC(); !got.Equal(target) {
				t.Errorf("X-MSFBL ObjectId reads back as %v, want %v", got, target)
			}

			if !m.Date().Equal(target) {
				t.Errorf("Date header reads back as %v, want %v", m.Date(), target)
			}
		})
	}
}

// TestRetimeSeedAgainstDeliveredMessages pins the retimed seed against the
// seeds the two delivered messages actually carry. The 3 Sep delivery was
// retimed from the source's send time, so its seed comes back byte for byte.
// The 30 Aug delivery was not: its seed ends 00, a whole second, which is what
// regenerating from the target produces and what a live send almost never does.
func TestRetimeSeedAgainstDeliveredMessages(t *testing.T) {
	tests := []struct {
		target    string
		delivered string // the seed the delivered message carries
		wantSeed  string // the seed retime produces from the source
		why       string
	}{
		{
			target:    "2026-09-03 16:35:21 +0000",
			delivered: "178845332169",
			wantSeed:  "178845332169",
			why:       "sub-second part survives, so a retime from the source reproduces it",
		},
		{
			target:    "2026-08-30 18:14:37 +0000",
			delivered: "178811367700",
			wantSeed:  "178811367769",
			why:       "the delivery's trailing 00 is a whole second: regenerated from the target, not retimed from the source's 690 ms",
		},
	}
	for _, tc := range tests {
		t.Run(tc.target, func(t *testing.T) {
			out, err := retime(fixture(), tc.target, nil)
			if err != nil {
				t.Fatalf("retime: %v", err)
			}
			m, err := mailmsg.Parse([]byte(out))
			if err != nil {
				t.Fatal(err)
			}
			seed, ok := m.MessageIDSeed()
			if !ok {
				t.Fatalf("no seed after retime:\n%s", out)
			}
			if seed.String() != tc.wantSeed {
				t.Errorf("seed = %s, want %s (%s)", seed.String(), tc.wantSeed, tc.why)
			}
		})
	}
}

// TestRetimeIsIdempotent: retiming an already-retimed message to the same
// target is a no-op, X-MSFBL included. If any carrier were left behind on the
// first pass, the second pass would move it and the two outputs would differ.
func TestRetimeIsIdempotent(t *testing.T) {
	want := retimeTargets[1]
	once, err := retime(fixture(), want, nil)
	if err != nil {
		t.Fatalf("first retime: %v", err)
	}
	twice, err := retime(once, want, nil)
	if err != nil {
		t.Fatalf("second retime: %v", err)
	}
	if once != twice {
		t.Errorf("retime is not idempotent:\n--- once ---\n%s\n--- twice ---\n%s", once, twice)
	}
}

// TestRetimeHonoursSeedUnit: a 13-digit seed counts milliseconds, not the
// centiseconds a 12-digit seed uses. Shifting it at the wrong scale would put
// the send date years away.
func TestRetimeHonoursSeedUnit(t *testing.T) {
	msg := "Date: Sun, 30 Aug 2026 18:14:37 -0000\n" +
		"Message-ID: <1788113677430.7.1@example.com>\n" +
		"\n" +
		"body\n"

	out, err := retime(msg, retimeTargets[1], nil)
	if err != nil {
		t.Fatalf("retime: %v", err)
	}
	m, err := mailmsg.Parse([]byte(out))
	if err != nil {
		t.Fatal(err)
	}
	seed, ok := m.MessageIDSeed()
	if !ok {
		t.Fatalf("no seed after retime:\n%s", out)
	}
	want := time.Date(2026, 9, 3, 16, 35, 21, 430*int(time.Millisecond), time.UTC)
	if !seed.At().Equal(want) {
		t.Errorf("seed = %v, want %v (sub-second part must survive the shift)", seed.At(), want)
	}
}

// TestRetimeRefusesAmbiguousSeedWidth: an 11-digit seed could be seconds or
// centiseconds, so retime refuses it instead of guessing.
func TestRetimeRefusesAmbiguousSeedWidth(t *testing.T) {
	msg := "Date: Sun, 30 Aug 2026 18:14:37 -0000\n" +
		"Message-ID: <17881136770.7.1@example.com>\n" +
		"\n" +
		"body\n"

	if _, err := retime(msg, retimeTargets[1], nil); err == nil {
		t.Fatal("retime shifted an ambiguous 11-digit seed, want an error")
	}
}

// wholeSecondDelivery is the Order Confirmation as delivered, verbatim: its
// Message-ID seed and its Gmail receipt time both land on an exact whole
// second. Neither was minted by a clock, which is the tell retime must not
// manufacture from a source that has sub-second precision of its own.
const wholeSecondDelivery = "Date: Sun, 30 Aug 2026 18:14:37 -0000\n" +
	"Message-ID: <178811367700.7.17946179276067562017@ip-172-21-223-177.ec2.internal>\n" +
	"X-Received: by 2002:a17:90b:3b88:b0:39d:efa9:cd25 with SMTP id\n" +
	" 98e67ed59e1d1-39e1e263458mr7388021a91.2.1788113678000;\n" +
	"       Sun, 30 Aug 2026 11:14:38 -0700 (PDT)\n" +
	"\n" +
	"Test message body\n"

// relayLine is a real Received line bearing the ecelerity (Momentum) queue ID
// the SparkPost MTA minted for this message. Its own date reads 30 Aug while
// the queue ID's time field, D73CAAA6 reversed, decodes to 16 Sep 16:27:41, so
// the ID restates the injection time in a form no other carrier shares and no
// stage recomputes.
const relayLine = "Received: from [52.202.1.10] ([52.202.1.10:48804] helo=ip-172-21-223-177.ec2.internal)" +
	" by i-05976ca9b34c43658.mta1vsmtp.sd.prd.sparkpost (envelope-from <bounces@bounce.eventbrite.com>)" +
	" (ecelerity 5.3.0.76417 r(msys-ecelerity:tags/5.3.0.14)) with ESMTPSA (cipher=AES-256-GCM)" +
	" id 5A/65-59472-D73CAAA6; Sun, 30 Aug 2026 18:14:37 +0000\n"

// TestRetimePinsRelayIDToTarget: the queue ID carries the injection time in its
// last 8 hex digits, reversed, and leaving it where it is leaves the original
// send time readable in the header, which is the one thing a retime exists to
// remove.
//
// It is pinned to the target rather than shifted by target-minus-Date, because
// it records the injection directly instead of deriving from Date, exactly as
// X-MSFBL does. On an honest message the two agree: one MTA writes the queue ID
// and the Date at the same instant. On a message whose Date has already moved,
// only pinning repairs it, since a shift moves the relay by the distance
// between its Date and the target and that distance is zero.
func TestRetimePinsRelayIDToTarget(t *testing.T) {
	tests := []struct {
		name   string
		date   string // the Date header as it stands
		target string // the retime target
	}{
		{
			name:   "honest message: Date and queue ID agree",
			date:   "Sun, 16 Sep 2026 16:27:41 +0000",
			target: retimeTargets[1],
		},
		{
			name:   "moved message: Date at the target, queue ID left at the injection",
			date:   "Sun, 30 Aug 2026 18:14:37 -0000",
			target: "2026-08-30 18:14:37 +0000",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			msg := "Date: " + tc.date + "\n" + relayLine + "\nTest message body\n"
			target, err := parseTarget("", tc.target)
			if err != nil {
				t.Fatal(err)
			}

			out, err := retime(msg, tc.target, nil)
			if err != nil {
				t.Fatalf("retime: %v", err)
			}
			if got := relayEpoch(t, out); !got.Equal(target) {
				t.Errorf("relay ID time = %v, want the target %v", got, target)
			}
			// The queue and job fields are not time-bearing: they identify the
			// relay session, so they must survive byte for byte.
			if !strings.Contains(out, "id 5A/65-59472-") {
				t.Errorf("relay ID lost its queue/job fields:\n%s", out)
			}
		})
	}
}

// TestRetimeLeavesUnreadableRelayField: an ID shaped like an ecelerity queue ID
// whose last 8 hex do not decode to a plausible time is not a carrier.
// Shifting it would corrupt an identifier that merely resembles one.
func TestRetimeLeavesUnreadableRelayField(t *testing.T) {
	msg := "Date: Sun, 30 Aug 2026 18:14:37 -0000\n" +
		"Received: from mta by mx.example with ESMTPS id 5A/65-59472-00000001; Sun, 30 Aug 2026 18:14:37 +0000\n" +
		"\n" +
		"body\n"

	out, err := retime(msg, retimeTargets[1], nil)
	if err != nil {
		t.Fatalf("retime: %v", err)
	}
	if !strings.Contains(out, "id 5A/65-59472-00000001;") {
		t.Errorf("retime shifted a relay field that is not a reversed Unix time:\n%s", out)
	}
}

// TestRetimeLeavesGmailSMTPID: Gmail's own SMTP id shares the "id <token>;"
// shape but carries no time, so it must not be mistaken for one.
func TestRetimeLeavesGmailSMTPID(t *testing.T) {
	msg := "Date: Sun, 30 Aug 2026 18:14:37 -0000\n" +
		"Received: by 2002:a05:123 with SMTP id ir1csp2824626vqb; Sun, 30 Aug 2026 18:14:38 +0000\n" +
		"\n" +
		"body\n"

	out, err := retime(msg, retimeTargets[1], nil)
	if err != nil {
		t.Fatalf("retime: %v", err)
	}
	if !strings.Contains(out, "id ir1csp2824626vqb;") {
		t.Errorf("retime rewrote Gmail's SMTP id:\n%s", out)
	}
}

// relayEpoch reads the injection time out of the queue ID in raw.
func relayEpoch(t *testing.T, raw string) time.Time {
	t.Helper()
	m := reQueueID.FindStringSubmatch(raw)
	if m == nil {
		t.Fatalf("no ecelerity queue ID in:\n%s", raw)
	}
	epoch, ok := queueEpoch(m[2])
	if !ok {
		t.Fatalf("queue ID field %q carries no readable time", m[2])
	}
	return time.Unix(epoch, 0).UTC()
}

// TestRetimeSeedsWholeSecondStamps: a retime that lands a sub-second-capable
// carrier on an exact whole second reproduces the signature of a timestamp
// regenerated from an integer, so retime seeds a non-zero sub-second part
// instead. The seeded value comes from text the retime does not move, so a
// rerun is byte-identical, and it is never zero, so the tell does not return.
func TestRetimeSeedsWholeSecondStamps(t *testing.T) {
	target, err := parseTarget("", retimeTargets[1])
	if err != nil {
		t.Fatal(err)
	}
	out, err := retime(wholeSecondDelivery, retimeTargets[1], nil)
	if err != nil {
		t.Fatalf("retime: %v", err)
	}
	m, err := mailmsg.Parse([]byte(out))
	if err != nil {
		t.Fatal(err)
	}

	seed, ok := m.MessageIDSeed()
	if !ok {
		t.Fatalf("no Message-ID seed after retime:\n%s", out)
	}
	if got := seed.At().Truncate(time.Second); !got.Equal(target) {
		t.Errorf("seed reads back as %v, want %v", got, target)
	}
	if seed.Fraction() == 0 {
		t.Errorf("seed %s still ends on a whole second", seed.String())
	}
	if len(seed.String()) != 12 {
		t.Errorf("seed width = %d digits, want 12: the centisecond unit changed", len(seed.String()))
	}

	tail := tailTime(t, out)
	if got := tail.Truncate(time.Second); !got.Equal(target.Add(time.Second)) {
		t.Errorf("X-Received receipt reads back as %v, want %v", got, target.Add(time.Second))
	}
	if tail.Nanosecond()%int(time.Millisecond) != 0 || tail.Nanosecond() == 0 {
		t.Errorf("X-Received receipt %v does not carry a non-zero millisecond part", tail)
	}
	if !tail.After(seed.At()) {
		t.Errorf("X-Received receipt %v is not after the send instant %v", tail, seed.At())
	}

	twice, err := retime(out, retimeTargets[1], nil)
	if err != nil {
		t.Fatalf("second retime: %v", err)
	}
	if out != twice {
		t.Errorf("seeding is not idempotent:\n--- once ---\n%s\n--- twice ---\n%s", out, twice)
	}
}

// TestRetimeSeedingKeysOnTheMessage: two messages sent at the same instant do
// not get the same seeded sub-second part, because the part is drawn from each
// message's own invariant text rather than from the date alone.
func TestRetimeSeedingKeysOnTheMessage(t *testing.T) {
	other := strings.Replace(wholeSecondDelivery,
		"17946179276067562017@ip-172-21-223-177.ec2.internal",
		"4788537881896003629@ip-172-21-213-153.ec2.internal", 1)

	seeds := map[string]string{}
	for _, msg := range []string{wholeSecondDelivery, other} {
		out, err := retime(msg, retimeTargets[1], nil)
		if err != nil {
			t.Fatalf("retime: %v", err)
		}
		m, err := mailmsg.Parse([]byte(out))
		if err != nil {
			t.Fatal(err)
		}
		seed, ok := m.MessageIDSeed()
		if !ok {
			t.Fatalf("no seed:\n%s", out)
		}
		seeds[seed.String()] = ""
	}
	if len(seeds) != 2 {
		t.Errorf("two messages at the same send date got the same seed: %v", seeds)
	}
}

// tailTime returns the millisecond receipt time Gmail wrote into the X-Received
// id.
func tailTime(t *testing.T, raw string) time.Time {
	t.Helper()
	m, err := mailmsg.Parse([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range m.Stamps() {
		if s.Source == "X-Received.tail" {
			return s.When
		}
	}
	t.Fatalf("no X-Received tail in:\n%s", raw)
	return time.Time{}
}

func mustHeaders(t *testing.T, raw string) string {
	t.Helper()
	h, _ := splitHeaders(raw)
	return h
}

// threeSepSource is a message shaped like the delivered cancellation: an
// unpadded day, a "-0000" Date (RFC 5322 §3.3's "no zone information", which is
// not the "+0000" that asserts UTC), and Gmail Received lines carrying the
// "(PDT)" comment Gmail writes. Every date string in it is one a real send
// produced, so nothing in it is the tool's own formatting.
const threeSepSource = "Date: Thu, 3 Sep 2026 16:35:21 -0000\n" +
	"Message-ID: <178845332169.7.4788537881896003629@ip-172-21-213-153.ec2.internal>\n" +
	"Received: from [52.202.1.10] ([52.202.1.10:14250] helo=ip-172-21-213-153.ec2.internal)\n" +
	" by i-0bcf48c53d19b440e.mta1vsmtp.sd.prd.sparkpost (envelope-from <bounces@bounce.eventbrite.com>)\n" +
	" (ecelerity 5.3.0.76417 r(msys-ecelerity:tags/5.3.0.14)) with ESMTPSA (cipher=AES-256-GCM)\n" +
	" id 98/A9-06036-9C1A99A6; Thu, 3 Sep 2026 16:35:21 +0000\n" +
	"Received: by 2002:a05:612c:2c01 with SMTP id ir1csp2824626vqb; Thu, 3 Sep 2026 09:35:23 -0700 (PDT)\n" +
	"X-Received: by 2002:a05:6a20:94ca:b0:3d3:b00b:26e8 with SMTP id\n" +
	" adf61e73a8af0-3dd5f8123f7mr8071326637.28.1788453322973;\n" +
	"       Thu, 3 Sep 2026 09:35:22 -0700 (PDT)\n" +
	"\n" +
	"Test message body\n"

// TestRetimePreservesDateTextShape pins what a retime must not do to a date
// string it has no need to change. Reformatting every date from a time.Time
// leaves three traces of the tool rather than of the mail system: a zero-padded
// day, a dropped "(PDT)" zone comment, and "-0000" promoted to "+0000".
func TestRetimePreservesDateTextShape(t *testing.T) {
	t.Run("a message already at the target comes back unchanged", func(t *testing.T) {
		// No --set: the target is read from X-MSFBL, which the fixture already
		// agrees with, so the delta is zero and no date needs rewriting.
		out, err := retime(fixture(), "", nil)
		if err != nil {
			t.Fatal(err)
		}
		if out != fixture() {
			t.Errorf("retime at delta 0 changed the message: %s", firstDiff(fixture(), out))
		}
	})

	t.Run("a moved date keeps its padding, offset text and comment", func(t *testing.T) {
		out, err := retime(threeSepSource, "2026-09-08 12:00:00 +0000", nil)
		if err != nil {
			t.Fatal(err)
		}
		// Each date moved by the same delta (three Sep 16:35:21 -> 8 Sep 12:00:00
		// UTC, +4d19h24m39s). The day is a single digit on both sides, so the
		// unpadded form is visible; the offsets are the ones the source wrote.
		for _, want := range []string{
			"Date: Tue, 8 Sep 2026 12:00:00 -0000\n",
			// The queue ID is pinned to the target, so it takes the target's time
			// rather than the source's; the date after the semicolon is the
			// source's own "+0000" kept as written.
			"id 98/A9-06036-0C8FF9A6; Tue, 8 Sep 2026 12:00:00 +0000\n",
			"with SMTP id ir1csp2824626vqb; Tue, 8 Sep 2026 05:00:02 -0700 (PDT)\n",
			"       Tue, 8 Sep 2026 05:00:01 -0700 (PDT)\n",
		} {
			if !strings.Contains(out, want) {
				t.Errorf("missing %q in:\n%s", want, out)
			}
		}
		if n := strings.Count(out, "-0700 (PDT)"); n != 2 {
			t.Errorf("found %d \"(PDT)\" comments, want 2: a comment was dropped:\n%s", n, out)
		}
		// The SparkPost Received line's own "+0000" is correct and stays, so the
		// trace to exclude is the one on the Date header, which was written
		// "-0000". The positive assertions above already pin both.
		for _, trace := range []string{"08 Sep", "Date: Tue, 8 Sep 2026 12:00:00 +0000\n"} {
			if strings.Contains(out, trace) {
				t.Errorf("output carries %q, a reformatting trace:\n%s", trace, out)
			}
		}
	})
}

// firstDiff renders the first differing line of two messages, so a failure
// reports the line that moved rather than the whole message.
func firstDiff(want, got string) string {
	wl, gl := strings.Split(want, "\n"), strings.Split(got, "\n")
	for i := 0; i < len(wl) || i < len(gl); i++ {
		var w, g string
		if i < len(wl) {
			w = wl[i]
		}
		if i < len(gl) {
			g = gl[i]
		}
		if w != g {
			return fmt.Sprintf("line %d:\n  want: %q\n  got:  %q", i+1, w, g)
		}
	}
	return "(identical)"
}

// TestRetimeZoneRewritesOnlyTheDateHeader: --zone re-renders the Date in the
// named zone at the same instant. Received lines keep the zones their own
// systems wrote, and the instant-valued carriers, which carry no zone, are
// untouched. The zone applies on a pure rezone (delta 0) as well as a move.
func TestRetimeZoneRewritesOnlyTheDateHeader(t *testing.T) {
	pdt, err := mailmsg.ParseZone("PDT")
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name        string
		target      string // "" reads the target off X-MSFBL: delta 0, pure rezone
		wantDate    string
		wantInstant time.Time // what the Date parses back to
		wantGmail   string    // Gmail's Received line: shifted, own zone kept
	}{
		{
			name:        "pure rezone at delta zero",
			target:      "2026-08-30 18:14:37 +0000",
			wantDate:    "Date: Sun, 30 Aug 2026 11:14:37 -0700\n",
			wantInstant: time.Date(2026, 8, 30, 18, 14, 37, 0, time.UTC),
			wantGmail:   "Sun, 30 Aug 2026 11:14:38 -0700 (PDT)",
		},
		{
			name:        "rezone alongside a move",
			target:      "2026-09-03 16:35:21 +0000",
			wantDate:    "Date: Thu, 3 Sep 2026 09:35:21 -0700\n",
			wantInstant: time.Date(2026, 9, 3, 16, 35, 21, 0, time.UTC),
			wantGmail:   "Thu, 3 Sep 2026 09:35:22 -0700 (PDT)",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			out, err := retime(wholeSecondDelivery, tc.target, pdt)
			if err != nil {
				t.Fatalf("retime: %v", err)
			}
			if !strings.Contains(out, tc.wantDate) {
				t.Errorf("Date not in the named zone; want %q in:\n%s", tc.wantDate, out)
			}
			// The zones the other systems wrote stay theirs.
			if !strings.Contains(out, tc.wantGmail) {
				t.Errorf("Gmail's Received line lost its own zone; want %q in:\n%s", tc.wantGmail, out)
			}
			// The instant-valued carriers still read the target instant.
			m, err := mailmsg.Parse([]byte(out))
			if err != nil {
				t.Fatal(err)
			}
			if d := m.Date(); !d.Equal(tc.wantInstant) {
				t.Errorf("Date parses back as %v, want %v: the rezone moved the instant", d, tc.wantInstant)
			}
			seed, ok := m.MessageIDSeed()
			if !ok {
				t.Fatalf("no seed:\n%s", out)
			}
			if got := seed.At().Truncate(time.Second); !got.Equal(tc.wantInstant) {
				t.Errorf("seed reads back as %v, want %v", got, tc.wantInstant)
			}
		})
	}
}

// TestRetimeZoneIANAWithDST: an IANA zone is resolved through the tz database,
// so a Date landing on the other side of a DST boundary takes the offset the
// zone actually has at that instant.
func TestRetimeZoneIANAWithDST(t *testing.T) {
	loc, err := mailmsg.ParseZone("America/Los_Angeles")
	if err != nil {
		t.Fatal(err)
	}
	// 16:35:21 UTC on 3 Nov 2026 is PST (-0800); the same zone was -0700 above.
	out, err := retime(wholeSecondDelivery, "2026-11-03 16:35:21 +0000", loc)
	if err != nil {
		t.Fatalf("retime: %v", err)
	}
	if !strings.Contains(out, "Date: Tue, 3 Nov 2026 08:35:21 -0800") {
		t.Errorf("DST not honoured:\n%s", out)
	}
}

// TestRetimeZoneRoundTripsThroughParse: the retimed Date still parses to the
// target instant, which is the property any downstream reader depends on.
func TestRetimeZoneRoundTripsThroughParse(t *testing.T) {
	pdt, err := mailmsg.ParseZone("PDT")
	if err != nil {
		t.Fatal(err)
	}
	out, err := retime(threeSepSource, retimeTargets[1], pdt)
	if err != nil {
		t.Fatalf("retime: %v", err)
	}
	m, err := mailmsg.Parse([]byte(out))
	if err != nil {
		t.Fatal(err)
	}
	want := time.Date(2026, 9, 3, 16, 35, 21, 0, time.UTC)
	if d := m.Date(); !d.Equal(want) {
		t.Errorf("Date = %v, want %v", d, want)
	}
}
