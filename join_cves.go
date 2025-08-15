package main

import (
	"context"
	"net/url"
	"sort"
	"strings"
	"time"
)

type IPEnrich struct {
	IP      string
	Port    int
	Product string
	Version string
	ASN     string
	Country string
	CPEs    []string
	TopCVE  *CVE
}

// productFromCPE extracts product and version from a CPE 2.3 string.
func productFromCPE(cpe string) (string, string) {
	parts := strings.Split(cpe, ":")
	if len(parts) >= 6 {
		return parts[4], parts[5]
	}
	return "", ""
}

func enrichWithCVEs(rec *IPEnrich, f *CVEFlags) error {
	if !f.JoinCVEs {
		return nil
	}
	if len(rec.CPEs) == 0 && rec.Product == "" {
		return nil
	}
	client := NewCVEDBClient(time.Duration(f.Timeout) * time.Second)
	ctx := context.Background()
	cvesMap := map[string]CVE{}
	for _, cpe := range rec.CPEs {
		q := url.Values{"cpe23": []string{cpe}}
		if f.KEV {
			q.Set("is_kev", "true")
		}
		if f.EPSSTop {
			q.Set("sort_by_epss", "true")
		}
		list, err := client.GetCVEs(ctx, q)
		if err != nil {
			continue
		}
		for _, c := range list {
			cvesMap[c.ID] = c
		}
	}
	if len(cvesMap) == 0 && rec.Product != "" {
		cpes, err := client.GetCPEs(ctx, rec.Product)
		if err == nil {
			for _, cpe := range cpes {
				q := url.Values{"cpe23": []string{cpe}}
				if f.KEV {
					q.Set("is_kev", "true")
				}
				if f.EPSSTop {
					q.Set("sort_by_epss", "true")
				}
				list, err := client.GetCVEs(ctx, q)
				if err != nil {
					continue
				}
				for _, c := range list {
					cvesMap[c.ID] = c
				}
			}
		}
	}
	if len(cvesMap) == 0 {
		return nil
	}
	cves := make([]CVE, 0, len(cvesMap))
	for _, c := range cvesMap {
		cves = append(cves, c)
	}
	sort.Slice(cves, func(i, j int) bool {
		ei, ej := 0.0, 0.0
		if cves[i].EPSS != nil {
			ei = *cves[i].EPSS
		}
		if cves[j].EPSS != nil {
			ej = *cves[j].EPSS
		}
		if ei == ej {
			ci, cj := 0.0, 0.0
			if cves[i].CVSS != nil {
				ci = *cves[i].CVSS
			}
			if cves[j].CVSS != nil {
				cj = *cves[j].CVSS
			}
			return ci > cj
		}
		return ei > ej
	})
	rec.TopCVE = &cves[0]
	return nil
}
