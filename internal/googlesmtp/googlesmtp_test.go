package googlesmtp

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestInspect_ValidBase64(t *testing.T) {
	// Sample X-Google-Smtp-Source value from a real message
	sample := "AGHT+IFxR8w1JkX6y3m+Z1a8bC9dEfGhIjKlMnOpQrStUvWxYz0123456789=="
	rep := Inspect(sample)

	if !rep.Present {
		t.Fatal("expected Present to be true")
	}
	if !rep.ValidBase64 {
		t.Errorf("expected ValidBase64 to be true")
	}
	if rep.DecodedBytes == 0 {
		t.Errorf("expected DecodedBytes > 0")
	}
	if rep.Status != "opaque_provider_metadata" {
		t.Errorf("status = %q, want opaque_provider_metadata", rep.Status)
	}
	if !strings.Contains(rep.Warning, "cannot be cryptographically verified") {
		t.Errorf("expected warning about unverified proprietary metadata")
	}
}

func TestInspect_InvalidBase64(t *testing.T) {
	sample := "this is clearly not base64 !!! ***"
	rep := Inspect(sample)

	if !rep.Present {
		t.Fatal("expected Present to be true")
	}
	if rep.ValidBase64 {
		t.Errorf("expected ValidBase64 to be false for non-base64")
	}
}

func TestGenerateMock(t *testing.T) {
	mock := GenerateMock(48, "MOCK")
	rep := Inspect(mock)

	if !rep.ValidBase64 {
		t.Fatal("mock should be valid base64")
	}
	if rep.DecodedBytes != 48 {
		t.Fatalf("decoded bytes = %d, want 48", rep.DecodedBytes)
	}
	raw, _ := base64.StdEncoding.DecodeString(mock)
	if !strings.HasPrefix(string(raw), "MOCK") {
		t.Errorf("mock raw should start with prefix MOCK")
	}
}
