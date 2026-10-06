// Package authres parses and evaluates RFC 8601 Authentication-Results headers.
package authres

import (
	"fmt"
	"strconv"
	"strings"
	"unicode"
)

// Header represents a parsed Authentication-Results header.
type Header struct {
	AuthservID string
	Version    int
	Results    []MethodResult
	Raw        string
}

// MethodResult represents one authentication method outcome (e.g. dkim=pass).
type MethodResult struct {
	Method  string            // dkim, spf, dmarc, arc, iprev, etc.
	Version string            // method version if specified (e.g. "1" in "dkim/1=pass")
	Result  string            // pass, fail, softfail, neutral, none, temperror, permerror
	Reason  string            // reason statement
	Comment string            // parenthesized comments
	Props   map[string]string // properties such as header.d, header.i, smtp.mailfrom
}

// Result returns the first MethodResult for the given method name, or nil if not found.
func (h *Header) Result(method string) *MethodResult {
	m := strings.ToLower(method)
	for i := range h.Results {
		if strings.ToLower(h.Results[i].Method) == m {
			return &h.Results[i]
		}
	}
	return nil
}

// Parse parses a raw Authentication-Results or ARC-Authentication-Results header.
func Parse(raw string) (*Header, error) {
	s := strings.TrimSpace(raw)
	// Strip header name prefix if present
	if idx := strings.Index(s, ":"); idx >= 0 {
		prefix := strings.ToLower(strings.TrimSpace(s[:idx]))
		if strings.Contains(prefix, "authentication-results") {
			s = strings.TrimSpace(s[idx+1:])
		}
	}

	// The header starts with <authserv-id> [version] ;
	semi := strings.Index(s, ";")
	if semi < 0 {
		return nil, fmt.Errorf("authres: missing semicolon after authserv-id")
	}

	pre := strings.TrimSpace(s[:semi])
	rest := s[semi+1:]

	// Extract comments from pre if any
	_, preNoComment := extractComments(pre)
	parts := strings.Fields(preNoComment)
	if len(parts) == 0 {
		return nil, fmt.Errorf("authres: missing authserv-id")
	}

	h := &Header{
		AuthservID: parts[0],
		Raw:        raw,
	}
	if len(parts) > 1 {
		if v, err := strconv.Atoi(parts[1]); err == nil {
			h.Version = v
		}
	}

	// Parse method sections separated by semicolons
	sections := splitBySemicolonOutsideQuotes(rest)
	for _, sec := range sections {
		sec = strings.TrimSpace(sec)
		if sec == "" || sec == "none" {
			continue
		}
		mr, err := parseMethodResult(sec)
		if err != nil {
			continue
		}
		if mr != nil {
			h.Results = append(h.Results, *mr)
		}
	}

	return h, nil
}

func parseMethodResult(sec string) (*MethodResult, error) {
	comments, cleaned := extractComments(sec)
	tokens := tokenize(cleaned)
	if len(tokens) == 0 {
		return nil, nil
	}

	first := tokens[0]
	if !strings.Contains(first, "=") {
		return nil, fmt.Errorf("malformed result %q", sec)
	}

	k, v, _ := strings.Cut(first, "=")
	method := strings.TrimSpace(k)
	version := ""
	if slash := strings.Index(method, "/"); slash >= 0 {
		version = method[slash+1:]
		method = method[:slash]
	}

	mr := &MethodResult{
		Method:  strings.ToLower(method),
		Version: version,
		Result:  strings.ToLower(strings.TrimSpace(v)),
		Comment: strings.TrimSpace(strings.Join(comments, "; ")),
		Props:   make(map[string]string),
	}

	for _, tok := range tokens[1:] {
		if !strings.Contains(tok, "=") {
			continue
		}
		pk, pv, _ := strings.Cut(tok, "=")
		pk = strings.ToLower(strings.TrimSpace(pk))
		pv = strings.TrimSpace(pv)
		pv = unquote(pv)
		if pk == "reason" {
			mr.Reason = pv
		} else {
			mr.Props[pk] = pv
		}
	}

	return mr, nil
}

func extractComments(s string) ([]string, string) {
	var comments []string
	var cleaned strings.Builder
	inQuote := false
	depth := 0
	var curComment strings.Builder

	for i := 0; i < len(s); i++ {
		ch := s[i]
		if ch == '"' && (i == 0 || s[i-1] != '\\') && depth == 0 {
			inQuote = !inQuote
			cleaned.WriteByte(ch)
			continue
		}
		if !inQuote {
			if ch == '(' {
				if depth > 0 {
					curComment.WriteByte(ch)
				}
				depth++
				continue
			}
			if ch == ')' && depth > 0 {
				depth--
				if depth == 0 {
					comments = append(comments, strings.TrimSpace(curComment.String()))
					curComment.Reset()
					continue
				}
				curComment.WriteByte(ch)
				continue
			}
		}
		if depth > 0 {
			curComment.WriteByte(ch)
		} else {
			cleaned.WriteByte(ch)
		}
	}
	return comments, cleaned.String()
}

func splitBySemicolonOutsideQuotes(s string) []string {
	var parts []string
	var cur strings.Builder
	inQuote := false

	for i := 0; i < len(s); i++ {
		ch := s[i]
		if ch == '"' && (i == 0 || s[i-1] != '\\') {
			inQuote = !inQuote
		}
		if ch == ';' && !inQuote {
			parts = append(parts, cur.String())
			cur.Reset()
			continue
		}
		cur.WriteByte(ch)
	}
	if cur.Len() > 0 {
		parts = append(parts, cur.String())
	}
	return parts
}

func tokenize(s string) []string {
	var tokens []string
	var cur strings.Builder
	inQuote := false

	for i := 0; i < len(s); i++ {
		ch := s[i]
		if ch == '"' && (i == 0 || s[i-1] != '\\') {
			inQuote = !inQuote
			cur.WriteByte(ch)
			continue
		}
		if unicode.IsSpace(rune(ch)) && !inQuote {
			if cur.Len() > 0 {
				tokens = append(tokens, cur.String())
				cur.Reset()
			}
			continue
		}
		cur.WriteByte(ch)
	}
	if cur.Len() > 0 {
		tokens = append(tokens, cur.String())
	}
	return tokens
}

func unquote(s string) string {
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		return s[1 : len(s)-1]
	}
	return s
}

// CompareInput carries verification context to compare against declared headers.
type CompareInput struct {
	TrustedAuthservIDs []string
	DKIMValid          bool
	DKIMDomain         string
	DKIMError          string
	ARCStatus          string // pass, fail, none
}

// CompareReport summarizes alignment between declared results and computed results.
type CompareReport struct {
	AuthservID      string   `json:"authserv_id"`
	TrustedBoundary bool     `json:"trusted_boundary"`
	DKIMMatch       bool     `json:"dkim_match"`
	ARCMatch        bool     `json:"arc_match"`
	Discrepancies   []string `json:"discrepancies,omitempty"`
}

// Compare checks whether declared header assertions align with actual computed results.
func Compare(h *Header, in CompareInput) CompareReport {
	rep := CompareReport{
		AuthservID: h.AuthservID,
		DKIMMatch:  true,
		ARCMatch:   true,
	}

	for _, t := range in.TrustedAuthservIDs {
		if strings.EqualFold(h.AuthservID, t) {
			rep.TrustedBoundary = true
			break
		}
	}
	if !rep.TrustedBoundary && len(in.TrustedAuthservIDs) > 0 {
		rep.Discrepancies = append(rep.Discrepancies,
			fmt.Sprintf("authserv-id %q is outside configured trust boundaries", h.AuthservID))
	}

	// Check DKIM alignment
	if dkim := h.Result("dkim"); dkim != nil {
		declaredPass := dkim.Result == "pass"
		if declaredPass != in.DKIMValid {
			rep.DKIMMatch = false
			if declaredPass && !in.DKIMValid {
				rep.Discrepancies = append(rep.Discrepancies,
					fmt.Sprintf("DKIM declared pass but verification failed (%s)", in.DKIMError))
			} else if !declaredPass && in.DKIMValid {
				rep.Discrepancies = append(rep.Discrepancies,
					fmt.Sprintf("DKIM declared %s but verification passed", dkim.Result))
			}
		}
		if domain, ok := dkim.Props["header.d"]; ok && in.DKIMDomain != "" {
			if !strings.EqualFold(domain, in.DKIMDomain) {
				rep.DKIMMatch = false
				rep.Discrepancies = append(rep.Discrepancies,
					fmt.Sprintf("DKIM declared domain %q does not match verified domain %q", domain, in.DKIMDomain))
			}
		}
	}

	// Check ARC alignment
	if arc := h.Result("arc"); arc != nil {
		declaredPass := arc.Result == "pass"
		computedPass := in.ARCStatus == "pass"
		if declaredPass != computedPass {
			rep.ARCMatch = false
			rep.Discrepancies = append(rep.Discrepancies,
				fmt.Sprintf("ARC declared %s but computed status is %s", arc.Result, in.ARCStatus))
		}
	}

	return rep
}
