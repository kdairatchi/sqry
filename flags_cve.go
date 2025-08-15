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
	return f
}

func (f *CVEFlags) anyCVEQuery() bool {
	return f.CVEID != "" || f.CPE != "" || f.Product != ""
}
