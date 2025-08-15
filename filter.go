package main

// Result represents enriched information about an IP address.
type Result struct {
	IP      string   `json:"ip"`
	Domain  string   `json:"domain,omitempty"`
	Org     string   `json:"org,omitempty"`
	ASN     string   `json:"asn,omitempty"`
	Country string   `json:"country,omitempty"`
	Ports   []int    `json:"ports,omitempty"`
	Banner  string   `json:"banner,omitempty"`
	CPEs    []string `json:"cpes,omitempty"`
	Product string   `json:"product,omitempty"`
	Version string   `json:"version,omitempty"`
	TopCVE  *CVE     `json:"top_cve,omitempty"`
}

// filterResults applies country, ASN and domain filters.
func filterResults(results []Result, cfg Config) []Result {
	filtered := make([]Result, 0, len(results))
	for _, r := range results {
		if cfg.Country != "" && !equalsIgnoreCase(r.Country, cfg.Country) {
			continue
		}
		if cfg.ASN != "" && r.ASN != cfg.ASN {
			continue
		}
		if cfg.HasDomain && r.Domain == "" {
			continue
		}
		filtered = append(filtered, r)
	}
	return filtered
}

func equalsIgnoreCase(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca := a[i]
		cb := b[i]
		if 'A' <= ca && ca <= 'Z' {
			ca += 'a' - 'A'
		}
		if 'A' <= cb && cb <= 'Z' {
			cb += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}
