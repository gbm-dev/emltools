// Command strip removes DKIM, ARC, Authentication-Results, and other tracking
// or cryptographic authentication headers from .eml files.
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"gbm.dev/emltools/internal/mutate"
)

type stripConfig struct {
	DKIM          bool
	ARC           bool
	AuthResults   bool
	SPF           bool
	Google        bool
	All           bool
	CustomHeaders string
}

func runStrip(raw []byte, cfg stripConfig) ([]byte, error) {
	// If no specific flag was selected and no custom headers, default to All
	allAuth := cfg.All
	if !cfg.DKIM && !cfg.ARC && !cfg.AuthResults && !cfg.SPF && !cfg.Google && cfg.CustomHeaders == "" {
		allAuth = true
	}

	var custom []string
	if cfg.CustomHeaders != "" {
		for _, h := range strings.Split(cfg.CustomHeaders, ",") {
			trimmed := strings.TrimSpace(h)
			if trimmed != "" {
				custom = append(custom, trimmed)
			}
		}
	}

	opts := mutate.StripOptions{
		DKIM:         cfg.DKIM,
		ARC:          cfg.ARC,
		AuthResults:  cfg.AuthResults,
		SPF:          cfg.SPF,
		GoogleSource: cfg.Google,
		AllAuth:      allAuth,
		Custom:       custom,
	}

	return mutate.StripBytes(raw, opts)
}

func runStripFile(path string, cfg stripConfig) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read file: %w", err)
	}
	return runStrip(raw, cfg)
}

func partition(args []string) (flags, rest []string) {
	boolean := map[string]bool{
		"-i": true, "--i": true,
		"-dkim": true, "--dkim": true,
		"-arc": true, "--arc": true,
		"-authres": true, "--authres": true,
		"-spf": true, "--spf": true,
		"-google": true, "--google": true,
		"-all": true, "--all": true,
		"-help": true, "--help": true, "-h": true,
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

func main() {
	flags, rest := partition(os.Args[1:])
	fs := flag.NewFlagSet("strip", flag.ExitOnError)
	out := fs.String("o", "", "output .eml path (default: stdout, or in-place with -i)")
	inPlace := fs.Bool("i", false, "modify input file in-place")
	dkim := fs.Bool("dkim", false, "strip DKIM-Signature headers")
	arc := fs.Bool("arc", false, "strip ARC headers (ARC-Seal, ARC-Message-Signature, ARC-Authentication-Results)")
	authRes := fs.Bool("authres", false, "strip Authentication-Results headers")
	spf := fs.Bool("spf", false, "strip Received-SPF headers")
	google := fs.Bool("google", false, "strip X-Google-Smtp-Source headers")
	all := fs.Bool("all", false, "strip all authentication and verification headers (default if no specific headers chosen)")
	headers := fs.String("headers", "", "comma-separated custom header names to strip")

	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: strip [options] <message.eml>")
		fmt.Fprintln(os.Stderr, "Options:")
		fs.PrintDefaults()
	}

	fs.Parse(flags)
	if len(rest) < 1 {
		fs.Usage()
		os.Exit(2)
	}

	filePath := rest[0]
	cfg := stripConfig{
		DKIM:          *dkim,
		ARC:           *arc,
		AuthResults:   *authRes,
		SPF:           *spf,
		Google:        *google,
		All:           *all,
		CustomHeaders: *headers,
	}

	stripped, err := runStripFile(filePath, cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "strip error: %v\n", err)
		os.Exit(1)
	}

	if *inPlace {
		if err := os.WriteFile(filePath, stripped, 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "write error: %v\n", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "stripped %s in-place\n", filePath)
		return
	}

	if *out != "" {
		if err := os.WriteFile(*out, stripped, 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "write error: %v\n", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "wrote stripped message to %s\n", *out)
		return
	}

	os.Stdout.Write(stripped)
}
