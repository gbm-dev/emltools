// Package googlesmtp inspects and generates mock values for the proprietary
// X-Google-Smtp-Source email header.
package googlesmtp

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"strings"

	"gbm.dev/emltools/internal/mailmsg"
)

// SourceReport carries the analysis of an X-Google-Smtp-Source header.
type SourceReport struct {
	Present      bool   `json:"present"`
	Raw          string `json:"raw,omitempty"`
	ValidBase64  bool   `json:"valid_base64"`
	DecodedBytes int    `json:"decoded_bytes,omitempty"`
	HexPreview   string `json:"hex_preview,omitempty"`
	Status       string `json:"status"`
	Warning      string `json:"warning"`
}

const (
	StatusOpaqueMetadata = "opaque_provider_metadata"
	WarningUnverified    = "Proprietary internal Google SMTP routing token; cannot be cryptographically verified offline."
)

// Inspect analyzes the raw value of an X-Google-Smtp-Source header.
func Inspect(val string) *SourceReport {
	v := strings.TrimSpace(val)
	if v == "" {
		return &SourceReport{
			Present: false,
			Status:  "absent",
		}
	}

	rep := &SourceReport{
		Present: true,
		Raw:     v,
		Status:  StatusOpaqueMetadata,
		Warning: WarningUnverified,
	}

	// Support standard padded, unpadded, or URL-safe base64 encodings
	vClean := strings.TrimRight(v, "=")
	data, err := base64.RawStdEncoding.DecodeString(vClean)
	if err != nil {
		data, err = base64.RawURLEncoding.DecodeString(vClean)
	}
	if err != nil {
		rep.ValidBase64 = false
		return rep
	}

	rep.ValidBase64 = true
	rep.DecodedBytes = len(data)

	previewLen := len(data)
	if previewLen > 16 {
		previewLen = 16
	}
	rep.HexPreview = hex.EncodeToString(data[:previewLen])
	if len(data) > 16 {
		rep.HexPreview += "..."
	}

	return rep
}

// Extract gathers all X-Google-Smtp-Source headers from a message and inspects them.
func Extract(msg *mailmsg.Message) []*SourceReport {
	var reports []*SourceReport
	for _, h := range msg.GetAll("X-Google-Smtp-Source") {
		reports = append(reports, Inspect(h.Value))
	}
	return reports
}

// GenerateMock generates a synthetic base64 mock string of the specified byte
// length with an optional prefix.
func GenerateMock(byteLen int, prefix string) string {
	if byteLen <= 0 {
		byteLen = 48
	}
	buf := make([]byte, byteLen)
	_, _ = rand.Read(buf)
	if prefix != "" {
		copy(buf, []byte(prefix))
	}
	return base64.StdEncoding.EncodeToString(buf)
}
