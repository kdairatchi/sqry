package main

import "flag"

type CVEFlags struct {
	CVEID    string
	CPE      string
	Product  string
	KEV      bool
	EPSSTop  bool
	Since    string
	Until    string
	CVEJSON  bool
	Pretty   bool
	JoinCVEs bool
	Limit    int
	Timeout  int
	// New features
	MinCVSS     float64
	MaxCVSS     float64
	MinEPSS     float64
	MaxEPSS     float64
	Severity    string  // low, medium, high, critical
	ExportCSV   bool
	ExportHTML  bool
	VulnSearch  string  // Search CVE descriptions
	ShowRefs    bool    // Show references
	ShowCWE     bool    // Show CWE information
	CacheTime   int     // Cache time in minutes
	StatsOnly   bool    // Show only statistics
}

func addCVEFlags(fs *flag.FlagSet) *CVEFlags {
	f := &CVEFlags{}
	fs.StringVar(&f.CVEID, "cve", "", "Fetch a specific CVE by ID (e.g. CVE-2021-44228)")
	fs.StringVar(&f.CPE, "cpe", "", "Fetch CVEs by CPE 2.3 string")
	fs.StringVar(&f.Product, "product", "", "Resolve product to CPEs then fetch CVEs")
	fs.BoolVar(&f.KEV, "kev", false, "Only Known Exploited Vulnerabilities")
	fs.BoolVar(&f.EPSSTop, "epss-top", false, "Sort by EPSS descending")
	fs.StringVar(&f.Since, "since", "", "Filter CVEs published on/after YYYY-MM-DD")
	fs.StringVar(&f.Until, "until", "", "Filter CVEs published on/before YYYY-MM-DD")
	fs.BoolVar(&f.CVEJSON, "cve-json", false, "Output CVEs as JSON")
	fs.BoolVar(&f.Pretty, "pretty", false, "Pretty-print JSON output")
	fs.BoolVar(&f.JoinCVEs, "join-cves", false, "Enrich IP mode with inferred CVEs via CPEs")
	fs.IntVar(&f.Timeout, "timeout", 20, "HTTP timeout for CVEDB requests (seconds)")
	
	// New enhanced CVE features
	fs.Float64Var(&f.MinCVSS, "min-cvss", 0.0, "Minimum CVSS score filter")
	fs.Float64Var(&f.MaxCVSS, "max-cvss", 10.0, "Maximum CVSS score filter")
	fs.Float64Var(&f.MinEPSS, "min-epss", 0.0, "Minimum EPSS score filter")
	fs.Float64Var(&f.MaxEPSS, "max-epss", 1.0, "Maximum EPSS score filter")
	fs.StringVar(&f.Severity, "severity", "", "Filter by severity: low, medium, high, critical")
	fs.BoolVar(&f.ExportCSV, "export-csv", false, "Export results to CSV format")
	fs.BoolVar(&f.ExportHTML, "export-html", false, "Export results to HTML report")
	fs.StringVar(&f.VulnSearch, "search", "", "Search in CVE descriptions")
	fs.BoolVar(&f.ShowRefs, "show-refs", false, "Show CVE references")
	fs.BoolVar(&f.ShowCWE, "show-cwe", false, "Show CWE information")
	fs.IntVar(&f.CacheTime, "cache-time", 60, "CVE cache time in minutes (default: 60)")
	fs.BoolVar(&f.StatsOnly, "stats-only", false, "Show only vulnerability statistics")
	return f
}

func (f *CVEFlags) anyCVEQuery() bool {
	return f.CVEID != "" || f.CPE != "" || f.Product != ""
}
