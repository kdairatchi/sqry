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
	Quiet       bool
	Verbose     bool
	NoCache     bool
	NoColor     bool
	ShodanTimeout int // Shodan API timeout in seconds
	Workers     int // Number of concurrent workers
	RateLimit   int // Rate limiting: requests per second (0 = no limit)
	RetryAttempts int // Number of retry attempts for failed requests
	BatchSize   int // Batch size for processing
	MaxResults  int // Maximum results to process
	DryRun      bool // Dry run mode for testing
	Parallel    int // Max parallel connections
	QuickScan   bool // Quick scan mode - basic info only
	DeepScan    bool // Deep scan mode - all enrichment
	FocusVulns  bool // Focus on vulnerable targets only
	TargetPorts string // Target specific ports (comma-separated)
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
	fs.BoolVar(&cfg.Quiet, "quiet", false, "Suppress progress indicators and banners")
	fs.BoolVar(&cfg.Verbose, "verbose", false, "Show detailed progress information")
	fs.BoolVar(&cfg.NoCache, "no-cache", false, "Disable result caching")
	fs.BoolVar(&cfg.NoColor, "no-color", false, "Disable colored output")
	fs.IntVar(&cfg.ShodanTimeout, "shodan-timeout", 60, "Shodan API timeout in seconds")
	fs.IntVar(&cfg.Workers, "workers", 10, "Number of concurrent workers (default: 10)")
	fs.IntVar(&cfg.RateLimit, "rate-limit", 0, "Rate limit: requests per second (0 = no limit)")
	fs.IntVar(&cfg.RetryAttempts, "retry-attempts", 3, "Number of retry attempts (default: 3)")
	fs.IntVar(&cfg.BatchSize, "batch-size", 50, "Batch size for processing (default: 50)")
	fs.IntVar(&cfg.MaxResults, "max-results", 10000, "Maximum results to process (default: 10000)")
	fs.BoolVar(&cfg.DryRun, "dry-run", false, "Dry run mode - show what would be done")
	fs.IntVar(&cfg.Parallel, "parallel", 20, "Max parallel connections (default: 20)")
	fs.BoolVar(&cfg.QuickScan, "quick", false, "Quick scan mode - basic info only")
	fs.BoolVar(&cfg.DeepScan, "deep", false, "Deep scan mode - all enrichment enabled")
	fs.BoolVar(&cfg.FocusVulns, "focus-vulns", false, "Focus on vulnerable targets only")
	fs.StringVar(&cfg.TargetPorts, "target-ports", "", "Target specific ports (comma-separated, e.g., 80,443,8080)")
	
	var showVersion bool
	fs.BoolVar(&showVersion, "version", false, "Show version information")
	fs.BoolVar(&showVersion, "v", false, "Show version information")

	fs.Usage = func() {
		usage := `sqry -q <query> [options]

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
  -v, --version        Show version information
      --quiet          Suppress progress indicators and banners
      --verbose        Show detailed progress information
      --no-cache       Disable result caching
      --no-color       Disable colored output
      --shodan-timeout S  Shodan API timeout in seconds (default: 60)
      --workers N      Number of concurrent workers (default: 10)
      --rate-limit N   Rate limit: requests per second (0 = no limit)
      --retry-attempts N  Number of retry attempts (default: 3)
      --batch-size N   Batch size for processing (default: 50)
      --max-results N  Maximum results to process (default: 10000)
      --dry-run        Dry run mode - show what would be done
      --parallel N     Max parallel connections (default: 20)
      --quick          Quick scan mode - basic info only
      --deep           Deep scan mode - all enrichment enabled
      --focus-vulns    Focus on vulnerable targets only
      --target-ports   Target specific ports (comma-separated, e.g., 80,443,8080)

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
      --min-cvss N     Minimum CVSS score filter
      --max-cvss N     Maximum CVSS score filter
      --min-epss N     Minimum EPSS score filter
      --max-epss N     Maximum EPSS score filter
      --severity LEVEL Filter by severity: low, medium, high, critical
      --export-csv     Export results to CSV format
      --export-html    Export results to HTML report
      --search TERM    Search in CVE descriptions
      --show-refs      Show CVE references
      --show-cwe       Show CWE information
      --cache-time M   CVE cache time in minutes (default: 60)
      --stats-only     Show only vulnerability statistics

Examples:
  sqry -q "apache" --limit 10
  sqry -q "ssl:true" --domains --with-domains
  sqry -q "nginx" --json --country US --limit 5
  sqry -q "http" --httpx --limit 20
  sqry --cve CVE-2016-10087 --cve-json --pretty
`
		fmt.Fprint(fs.Output(), usage)
	}

	if err := fs.Parse(args); err != nil {
		return cfg, cve, err
	}
	
	if showVersion {
		printBanner()
		fmt.Println("\nFeatures:")
		fmt.Println("  ✓ Shodan IP extraction with smart filtering")
		fmt.Println("  ✓ CVE vulnerability intelligence")
		fmt.Println("  ✓ Concurrent processing for speed")
		fmt.Println("  ✓ Multiple output formats (JSON, CSV, TSV)")
		fmt.Println("  ✓ HTTP probing with httpx integration")
		fmt.Println("  ✓ Geolocation and ASN enrichment")
		fmt.Println("")
		return cfg, cve, fmt.Errorf("version info displayed")
	}

	// Quality-of-life: --with-domains implies --domains
	if cfg.WithDomains {
		cfg.Domains = true
	}
	
	// Quick scan mode - minimal enrichment for speed
	if cfg.QuickScan {
		cfg.Workers = 20 // More workers for speed
		cfg.Parallel = 50
		cfg.RateLimit = 0 // No rate limiting in quick mode
	}
	
	// Deep scan mode - maximum enrichment
	if cfg.DeepScan {
		cfg.Domains = true
		cfg.Ports = true
		cfg.Geo = true
		cfg.HTTPX = true
		cve.JoinCVEs = true
		cfg.Workers = 5 // Fewer workers to be gentle on APIs
		cfg.RateLimit = 2 // Rate limit for stability
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

	// Validate ASN format (if provided)
	if cfg.ASN != "" {
		if !strings.HasPrefix(cfg.ASN, "AS") || len(cfg.ASN) < 3 {
			return cfg, cve, errors.New("invalid --asn: must be in format AS#### (e.g. AS15169)")
		}
		// Validate that the part after AS is numeric
		asnNum := cfg.ASN[2:]
		for _, r := range asnNum {
			if r < '0' || r > '9' {
				return cfg, cve, errors.New("invalid --asn: must be in format AS#### (e.g. AS15169)")
			}
		}
	}

	// Validate numeric parameters
	if cfg.Workers <= 0 {
		return cfg, cve, errors.New("invalid --workers: must be greater than 0")
	}
	if cfg.RateLimit < 0 {
		return cfg, cve, errors.New("invalid --rate-limit: must be 0 or greater")
	}
	if cfg.RetryAttempts < 0 {
		return cfg, cve, errors.New("invalid --retry-attempts: must be 0 or greater")
	}
	if cfg.BatchSize <= 0 {
		return cfg, cve, errors.New("invalid --batch-size: must be greater than 0")
	}
	if cfg.MaxResults <= 0 {
		return cfg, cve, errors.New("invalid --max-results: must be greater than 0")
	}
	if cfg.ShodanTimeout <= 0 {
		return cfg, cve, errors.New("invalid --shodan-timeout: must be greater than 0")
	}
	if cfg.Limit < 0 {
		return cfg, cve, errors.New("invalid --limit: must be 0 or greater")
	}
	if cfg.Parallel <= 0 {
		return cfg, cve, errors.New("invalid --parallel: must be greater than 0")
	}

	// Validate CVE parameters
	if cve.Timeout <= 0 {
		return cfg, cve, errors.New("invalid --timeout: must be greater than 0")
	}
	if cve.MinCVSS < 0 || cve.MinCVSS > 10 {
		return cfg, cve, errors.New("invalid --min-cvss: must be between 0 and 10")
	}
	if cve.MaxCVSS < 0 || cve.MaxCVSS > 10 {
		return cfg, cve, errors.New("invalid --max-cvss: must be between 0 and 10")
	}
	if cve.MinCVSS > cve.MaxCVSS {
		return cfg, cve, errors.New("invalid CVSS range: --min-cvss cannot be greater than --max-cvss")
	}
	if cve.MinEPSS < 0 || cve.MinEPSS > 1 {
		return cfg, cve, errors.New("invalid --min-epss: must be between 0 and 1")
	}
	if cve.MaxEPSS < 0 || cve.MaxEPSS > 1 {
		return cfg, cve, errors.New("invalid --max-epss: must be between 0 and 1")
	}
	if cve.MinEPSS > cve.MaxEPSS {
		return cfg, cve, errors.New("invalid EPSS range: --min-epss cannot be greater than --max-epss")
	}
	if cve.Severity != "" {
		validSeverities := []string{"low", "medium", "high", "critical"}
		valid := false
		severityLower := strings.ToLower(cve.Severity)
		for _, v := range validSeverities {
			if severityLower == v {
				valid = true
				cve.Severity = severityLower
				break
			}
		}
		if !valid {
			return cfg, cve, errors.New("invalid --severity: must be one of low, medium, high, critical")
		}
	}
	if cve.CacheTime <= 0 {
		return cfg, cve, errors.New("invalid --cache-time: must be greater than 0")
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
