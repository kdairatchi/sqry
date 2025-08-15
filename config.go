package main

import (
	"errors"
	"flag"
	"fmt"
	"strings"
)

// Config holds command line options.
type Config struct {
	Query       string
	Domains     bool
	WithDomains bool
	JSON        bool
	Ports       bool
	Limit       int
	NoUARotate  bool
	Shuffle     bool
	SaveFile    string
	Country     string
	ASN         string
	HasDomain   bool
	Geo         bool
	HTTPX       bool
}

// parseFlags parses command line flags into Config and CVE options.
func parseFlags(args []string) (Config, *CVEFlags, error) {
	var cfg Config
	fs := flag.NewFlagSet("sqry", flag.ContinueOnError)

	// Add CVE flags (from your CVEDB integration)
	cve := addCVEFlags(fs)

	// Core sqry flags
	fs.StringVar(&cfg.Query, "q", "", "Shodan query")
	fs.BoolVar(&cfg.Domains, "domains", false, "Lookup domains for each IP")
	fs.BoolVar(&cfg.Domains, "d", false, "Lookup domains for each IP (alias)")
	fs.BoolVar(&cfg.WithDomains, "with-domains", false, "Output IP and domain pairs in CSV format")
	fs.BoolVar(&cfg.JSON, "json", false, "Output JSON with fields ip, domain, org, asn, country, port, banner, title, screenshot")
	fs.BoolVar(&cfg.Ports, "ports", false, "Include open ports for each IP")
	fs.IntVar(&cfg.Limit, "limit", 0, "Limit results to N IPs")
	fs.BoolVar(&cfg.NoUARotate, "no-ua-rotate", false, "Disable User-Agent rotation")
	fs.BoolVar(&cfg.Shuffle, "shuffle", false, "Randomize output order")
	fs.StringVar(&cfg.SaveFile, "save", "", "Save results to a file")
	fs.StringVar(&cfg.Country, "country", "", "Filter by 2-letter country code")
	fs.StringVar(&cfg.ASN, "asn", "", "Filter by ASN")
	fs.BoolVar(&cfg.HasDomain, "has-domain", false, "Only include results with a domain")
	fs.BoolVar(&cfg.Geo, "geo", false, "Include geolocation info")
	fs.BoolVar(&cfg.HTTPX, "httpx", false, "Probe targets with httpx for title and screenshots")

	fs.Usage = func() {
		usage := `sqry -q <query> [options]`

Options:
  -q string            Shodan query
  -d, --domains        Lookup domains for each IP
      --with-domains   Output IP and domain pairs in CSV format
      --json           Output JSON with fields ip, domain, org, asn, country, port, banner, title, screenshot
      --ports          Include open ports for each IP
      --limit N        Limit results to first N IPs
      --no-ua-rotate   Disable User-Agent rotation
      --shuffle        Randomize output order
      --save FILE      Save results to a specified file
      --country XX     Filter by 2-letter country code
      --asn ASN        Filter by ASN
      --has-domain     Only include results with a resolvable domain
      --geo            Include geolocation info
      --httpx          Enrich targets with title and screenshot via httpx

CVE options (CVEDB, no key required):
      --cve ID         Fetch a specific CVE by ID
      --cpe CPE23      Fetch CVEs by CPE 2.3 string
      --product NAME   Resolve product to CPEs then fetch CVEs
      --kev            Only Known Exploited Vulnerabilities
      --epss-top       Sort by EPSS descending
      --since DATE     Filter CVEs published on/after YYYY-MM-DD
      --until DATE     Filter CVEs published on/before YYYY-MM-DD
      --cve-json       Output CVEs as JSON
      --pretty         Pretty-print JSON output
      --join-cves      Enrich IP mode with inferred CVEs via CPEs
      --timeout S      HTTP timeout for CVEDB requests (seconds)

Examples:
  sqry -q "apache" --limit 10
  sqry -q "ssl:true" --domains --with-domains
  sqry -q "nginx" --json --country US --limit 5
  sqry -q "http" --httpx --limit 20
  sqry --cve CVE-2016-10087 --cve-json --pretty

		fmt.Fprint(fs.Output(), usage)
	}

	if err := fs.Parse(args); err != nil {
		return cfg, cve, err
	}

	// Quality-of-life: --with-domains implies --domains
	if cfg.WithDomains {
		cfg.Domains = true
	}

	// Pass global limit into CVE mode too (nice UX)
	cve.Limit = cfg.Limit

	// Validate country (if provided): must be 2 letters
	if cfg.Country != "" {
		if len(cfg.Country) != 2 || !isAllLetters(cfg.Country) {
			return cfg, cve, errors.New("invalid --country: must be a 2-letter code, e.g. US")
		}
		// normalize to upper
		cfg.Country = strings.ToUpper(cfg.Country)
	}

	// Two operating modes:
	// 1) Shodan/IP mode -> requires -q
	// 2) CVE mode -> allowed without -q when any CVE flag is used
	if cfg.Query == "" && !cve.anyCVEQuery() {
		return cfg, cve, errors.New("query required (-q) or provide CVE mode flags (e.g. --cve / --cpe / --product)")
	}

	return cfg, cve, nil
}

// helper: simple ASCII letter check
func isAllLetters(s string) bool {
	for _, r := range s {
		if r < 'A' || (r > 'Z' && r < 'a') || r > 'z' {
			return false
		}
	}
	return true
}
