package mutate

import (
	"strings"
	"testing"

	"gbm.dev/emltools/internal/mailmsg"
)

const sampleMsg = "From: sender@example.com\r\n" +
	"To: recipient@example.com\r\n" +
	"Subject: Hello World\r\n" +
	"Date: Mon, 14 Sep 2026 12:00:00 +0000\r\n" +
	"\r\n" +
	"Hello, this is the original body text.\r\n"

func TestMutate_ReplaceText(t *testing.T) {
	msg, err := mailmsg.Parse([]byte(sampleMsg))
	if err != nil {
		t.Fatal(err)
	}

	res, err := Apply(msg, Options{
		ReplaceText: map[string]string{
			"original body text": "MODIFIED body text",
		},
	})
	if err != nil {
		t.Fatalf("Apply failed: %v", err)
	}

	if !strings.Contains(string(res.RawBody), "MODIFIED body text") {
		t.Errorf("body text was not replaced, got %q", string(res.RawBody))
	}
	if strings.Contains(string(res.RawBody), "original body text") {
		t.Errorf("original body text still found in body")
	}
}

func TestMutate_AppendAndPrepend(t *testing.T) {
	msg, err := mailmsg.Parse([]byte(sampleMsg))
	if err != nil {
		t.Fatal(err)
	}

	res, err := Apply(msg, Options{
		PrependBody: "[NOTICE: External Sender]\r\n\r\n",
		AppendBody:  "\r\n--\r\nUnsubscribe here\r\n",
	})
	if err != nil {
		t.Fatal(err)
	}

	bodyStr := string(res.RawBody)
	if !strings.HasPrefix(bodyStr, "[NOTICE: External Sender]") {
		t.Errorf("body missing prepended text")
	}
	if !strings.HasSuffix(bodyStr, "Unsubscribe here\r\n") {
		t.Errorf("body missing appended text")
	}
}

func TestMutate_Headers(t *testing.T) {
	msg, err := mailmsg.Parse([]byte(sampleMsg))
	if err != nil {
		t.Fatal(err)
	}

	res, err := Apply(msg, Options{
		HeadersToAdd: [][2]string{
			{"X-Custom-Test", "Value123"},
		},
		HeadersToRemove: []string{"Subject"},
	})
	if err != nil {
		t.Fatal(err)
	}

	if res.Get("X-Custom-Test") != "Value123" {
		t.Errorf("X-Custom-Test header not found")
	}
	if res.Get("Subject") != "" {
		t.Errorf("Subject header was not removed")
	}
}

func TestStripHeaders(t *testing.T) {
	raw := "From: alice@example.com\r\n" +
		"To: bob@example.com\r\n" +
		"Subject: Auth Test\r\n" +
		"DKIM-Signature: v=1; a=rsa-sha256; d=example.com; b=abc...\r\n" +
		"ARC-Seal: i=1; a=rsa-sha256; d=example.com; b=xyz...\r\n" +
		"ARC-Message-Signature: i=1; a=rsa-sha256; d=example.com; b=123...\r\n" +
		"ARC-Authentication-Results: i=1; mx.google.com; dkim=pass\r\n" +
		"Authentication-Results: mx.google.com; dkim=pass\r\n" +
		"Received-SPF: pass client-ip=1.2.3.4\r\n" +
		"X-Google-Smtp-Source: ABCDEF123456\r\n" +
		"\r\n" +
		"Message body here\r\n"

	msg, err := mailmsg.Parse([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}

	// 1. Test stripping DKIM only
	resDKIM, err := StripHeaders(msg, StripOptions{DKIM: true})
	if err != nil {
		t.Fatal(err)
	}
	if resDKIM.Get("DKIM-Signature") != "" {
		t.Errorf("DKIM-Signature should be stripped")
	}
	if resDKIM.Get("ARC-Seal") == "" {
		t.Errorf("ARC-Seal should still be present")
	}

	// 2. Test stripping ARC only
	resARC, err := StripHeaders(msg, StripOptions{ARC: true})
	if err != nil {
		t.Fatal(err)
	}
	if resARC.Get("ARC-Seal") != "" || resARC.Get("ARC-Message-Signature") != "" || resARC.Get("ARC-Authentication-Results") != "" {
		t.Errorf("ARC headers should be stripped")
	}
	if resARC.Get("DKIM-Signature") == "" {
		t.Errorf("DKIM-Signature should still be present")
	}

	// 3. Test stripping AllAuth
	resAll, err := StripHeaders(msg, StripOptions{AllAuth: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, hdr := range []string{
		"DKIM-Signature", "ARC-Seal", "ARC-Message-Signature",
		"ARC-Authentication-Results", "Authentication-Results",
		"Received-SPF", "X-Google-Smtp-Source",
	} {
		if resAll.Get(hdr) != "" {
			t.Errorf("header %q should have been stripped by AllAuth", hdr)
		}
	}
	if resAll.Get("From") != "alice@example.com" {
		t.Errorf("From header should be preserved")
	}
	if string(resAll.RawBody) != "Message body here\r\n" {
		t.Errorf("body should be preserved")
	}
}
