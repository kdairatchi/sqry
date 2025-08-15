package main

import "time"

// CVE represents a vulnerability entry from Shodan's CVE database.
type CVE struct {
	ID                 string    `json:"cve_id"`
	Summary            *string   `json:"summary,omitempty"`
	CVSS               *float64  `json:"cvss,omitempty"`
	CVSSVersion        *float64  `json:"cvss_version,omitempty"`
	CVSSv2             *float64  `json:"cvss_v2,omitempty"`
	CVSSv3             *float64  `json:"cvss_v3,omitempty"`
	EPSS               *float64  `json:"epss,omitempty"`
	RankingEPSS        *float64  `json:"ranking_epss,omitempty"`
	KEV                bool      `json:"kev"`
	ProposeAction      *string   `json:"propose_action,omitempty"`
	RansomwareCampaign *string   `json:"ransomware_campaign,omitempty"`
	References         []string  `json:"references"`
	PublishedTime      time.Time `json:"published_time"`
	CPEs               []string  `json:"cpes,omitempty"`
}

type CVEsResp struct {
	CVEs []CVE `json:"cves"`
}

type TotalResp struct {
	Total *int `json:"total"`
}

type CPEsResp struct {
	CPEs  []string `json:"cpes"`
	Total *int     `json:"total,omitempty"`
}
