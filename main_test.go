package main

import "testing"

func TestParseFlags(t *testing.T) {
	cfg, cve, err := parseFlags([]string{"-q", "test", "--domains", "--limit", "5", "--country", "US", "--asn", "AS123"})
	if err != nil {
		t.Fatalf("parseFlags error: %v", err)
	}
	if !cfg.Domains || cfg.Limit != 5 || cfg.Country != "US" || cfg.ASN != "AS123" || cve == nil {
		t.Fatalf("unexpected config: %+v cve:%+v", cfg, cve)
	}
}

func TestParseFlagsNoQuery(t *testing.T) {
	if _, _, err := parseFlags([]string{"--domains"}); err == nil {
		t.Fatalf("expected error for missing query")
	}
}

func TestParseFlagsCVEOnly(t *testing.T) {
	cfg, cve, err := parseFlags([]string{"--cve", "CVE-1"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Query != "" || cve.CVEID != "CVE-1" {
		t.Fatalf("unexpected parse result: cfg=%+v cve=%+v", cfg, cve)
	}
}

func TestFilterResults(t *testing.T) {
	results := []Result{
		{IP: "1.1.1.1", Country: "US", ASN: "AS1", Domain: "a"},
		{IP: "2.2.2.2", Country: "FR", ASN: "AS2", Domain: ""},
	}
	cfg := Config{Country: "US", ASN: "AS1", HasDomain: true}
	filtered := filterResults(results, cfg)
	if len(filtered) != 1 || filtered[0].IP != "1.1.1.1" {
		t.Fatalf("unexpected filter result: %+v", filtered)
	}
}
