package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const sampleEmail = "From: alice@example.com\r\n" +
	"To: bob@example.com\r\n" +
	"Subject: Test Strip\r\n" +
	"Date: Wed, 16 Sep 2026 12:00:00 +0000\r\n" +
	"DKIM-Signature: v=1; a=rsa-sha256; d=example.com; b=abc...\r\n" +
	"ARC-Seal: i=1; a=rsa-sha256; d=example.com; b=xyz...\r\n" +
	"ARC-Message-Signature: i=1; a=rsa-sha256; d=example.com; b=123...\r\n" +
	"ARC-Authentication-Results: i=1; mx.google.com; dkim=pass\r\n" +
	"Authentication-Results: mx.google.com; dkim=pass\r\n" +
	"Received-SPF: pass client-ip=1.2.3.4\r\n" +
	"X-Google-Smtp-Source: ABCDEF123456\r\n" +
	"X-Custom-Tracking: track-999\r\n" +
	"\r\n" +
	"Here is the body content.\r\n"

func TestRunStrip_All(t *testing.T) {
	out, err := runStrip([]byte(sampleEmail), stripConfig{All: true})
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	for _, h := range []string{
		"DKIM-Signature:", "ARC-Seal:", "ARC-Message-Signature:",
		"ARC-Authentication-Results:", "Authentication-Results:",
		"Received-SPF:", "X-Google-Smtp-Source:",
	} {
		if strings.Contains(s, h) {
			t.Errorf("expected %q to be stripped, got:\n%s", h, s)
		}
	}
	if !strings.Contains(s, "From: alice@example.com") {
		t.Errorf("expected From header to remain")
	}
	if !strings.Contains(s, "X-Custom-Tracking: track-999") {
		t.Errorf("expected custom header to remain when not targeted")
	}
	if !strings.Contains(s, "Here is the body content.") {
		t.Errorf("expected body content to remain")
	}
}

func TestRunStrip_DKIMOnly(t *testing.T) {
	out, err := runStrip([]byte(sampleEmail), stripConfig{DKIM: true})
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if strings.Contains(s, "DKIM-Signature:") {
		t.Errorf("expected DKIM-Signature to be stripped")
	}
	if !strings.Contains(s, "ARC-Seal:") {
		t.Errorf("expected ARC-Seal to remain")
	}
	if !strings.Contains(s, "Authentication-Results:") {
		t.Errorf("expected Authentication-Results to remain")
	}
}

func TestRunStrip_ARCOnly(t *testing.T) {
	out, err := runStrip([]byte(sampleEmail), stripConfig{ARC: true})
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if strings.Contains(s, "ARC-Seal:") || strings.Contains(s, "ARC-Message-Signature:") {
		t.Errorf("expected ARC to be stripped")
	}
	if !strings.Contains(s, "DKIM-Signature:") {
		t.Errorf("expected DKIM-Signature to remain")
	}
}

func TestRunStrip_Custom(t *testing.T) {
	out, err := runStrip([]byte(sampleEmail), stripConfig{
		CustomHeaders: "X-Custom-Tracking,Subject",
	})
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if strings.Contains(s, "X-Custom-Tracking:") || strings.Contains(s, "Subject:") {
		t.Errorf("expected custom headers to be stripped")
	}
	if !strings.Contains(s, "DKIM-Signature:") {
		t.Errorf("expected DKIM to remain when only custom specified")
	}
}

func TestStripInPlace(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "test.eml")
	if err := os.WriteFile(filePath, []byte(sampleEmail), 0o644); err != nil {
		t.Fatal(err)
	}

	out, err := runStripFile(filePath, stripConfig{All: true})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "DKIM-Signature:") {
		t.Errorf("expected DKIM-Signature to be stripped")
	}
}
