// Package mutate provides helpers for mutating email bodies and headers while
// strictly preserving RFC 5322 CRLF wire-format structure.
package mutate

import (
	"bytes"
	"fmt"
	"strings"

	"gbm.dev/emltools/internal/mailmsg"
)

// Options configures message mutations.
type Options struct {
	ReplaceText      map[string]string // string -> replacement
	AppendBody       string
	PrependBody      string
	SetBody          []byte
	HeadersToAdd     [][2]string // [Name, Value]
	HeadersToRemove  []string
	HeadersToReplace map[string]string // Name -> NewValue
}

// Apply transforms an existing message according to opts and returns a newly parsed Message.
func Apply(msg *mailmsg.Message, opts Options) (*mailmsg.Message, error) {
	// 1. Process Body
	var body []byte
	if opts.SetBody != nil {
		body = opts.SetBody
	} else {
		body = append([]byte{}, msg.RawBody...)
		if len(opts.ReplaceText) > 0 {
			bodyStr := string(body)
			for oldStr, newStr := range opts.ReplaceText {
				bodyStr = strings.ReplaceAll(bodyStr, oldStr, newStr)
			}
			body = []byte(bodyStr)
		}
		if opts.PrependBody != "" {
			body = append([]byte(toCRLF(opts.PrependBody)), body...)
		}
		if opts.AppendBody != "" {
			body = append(body, []byte(toCRLF(opts.AppendBody))...)
		}
	}

	// 2. Process Headers
	removeSet := make(map[string]bool)
	for _, h := range opts.HeadersToRemove {
		removeSet[strings.ToLower(h)] = true
	}

	var headerBuf bytes.Buffer

	// Write existing headers that are not removed
	for _, h := range msg.Headers {
		nameLower := strings.ToLower(h.Name)
		if removeSet[nameLower] {
			continue
		}
		if newVal, ok := opts.HeadersToReplace[h.Name]; ok {
			headerBuf.WriteString(fmt.Sprintf("%s: %s\r\n", h.Name, newVal))
			continue
		}
		headerBuf.Write(h.Raw)
		headerBuf.WriteString("\r\n")
	}

	// Append added headers
	for _, pair := range opts.HeadersToAdd {
		headerBuf.WriteString(fmt.Sprintf("%s: %s\r\n", pair[0], pair[1]))
	}

	// 3. Assemble complete message: Headers + \r\n + Body
	full := append(headerBuf.Bytes(), append([]byte("\r\n"), body...)...)
	return mailmsg.Parse(full)
}

// StripOptions configures which authentication or tracking headers to remove.
type StripOptions struct {
	DKIM         bool     // Strips DKIM-Signature
	ARC          bool     // Strips ARC-Seal, ARC-Message-Signature, ARC-Authentication-Results
	AuthResults  bool     // Strips Authentication-Results
	SPF          bool     // Strips Received-SPF
	GoogleSource bool     // Strips X-Google-Smtp-Source
	AllAuth      bool     // Strips all standard authentication & verification headers
	Custom       []string // Custom header names to remove
}

// AuthHeaderNames returns the list of header names matching the given StripOptions.
func AuthHeaderNames(opts StripOptions) []string {
	var names []string
	if opts.AllAuth || opts.DKIM {
		names = append(names, "DKIM-Signature")
	}
	if opts.AllAuth || opts.ARC {
		names = append(names, "ARC-Seal", "ARC-Message-Signature", "ARC-Authentication-Results")
	}
	if opts.AllAuth || opts.AuthResults {
		names = append(names, "Authentication-Results")
	}
	if opts.AllAuth || opts.SPF {
		names = append(names, "Received-SPF")
	}
	if opts.AllAuth || opts.GoogleSource {
		names = append(names, "X-Google-Smtp-Source")
	}
	names = append(names, opts.Custom...)
	return names
}

// StripHeaders removes headers specified by opts from msg.
func StripHeaders(msg *mailmsg.Message, opts StripOptions) (*mailmsg.Message, error) {
	return Apply(msg, Options{
		HeadersToRemove: AuthHeaderNames(opts),
	})
}

// StripBytes operates directly on raw RFC 5322 byte slices.
func StripBytes(raw []byte, opts StripOptions) ([]byte, error) {
	msg, err := mailmsg.Parse(raw)
	if err != nil {
		return nil, err
	}
	res, err := StripHeaders(msg, opts)
	if err != nil {
		return nil, err
	}
	return res.Raw, nil
}

func toCRLF(s string) string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	return strings.ReplaceAll(s, "\n", "\r\n")
}
