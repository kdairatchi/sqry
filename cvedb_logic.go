package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"
)

func cveParams(f *CVEFlags) url.Values {
	q := url.Values{}
	if f.CPE != "" {
		q.Set("cpe23", f.CPE)
	}
	if f.KEV {
		q.Set("is_kev", "true")
	}
	if f.EPSSTop {
		q.Set("sort_by_epss", "true")
	}
	if f.Since != "" || f.Until != "" {
		if f.Since != "" {
			q.Set("start_date", f.Since)
		}
		if f.Until != "" {
			q.Set("end_date", f.Until)
		}
	}
	return q
}

func runCVEQuery(f *CVEFlags) error {
	ctx := context.Background()
	client := NewCVEDBClient(time.Duration(f.Timeout) * time.Second)

	var cves []CVE

	switch {
	case f.CVEID != "":
		cve, err := client.GetCVE(ctx, f.CVEID)
		if err != nil {
			return err
		}
		cves = []CVE{*cve}
	case f.CPE != "":
		var err error
		cves, err = client.GetCVEs(ctx, cveParams(f))
		if err != nil {
			return err
		}
	case f.Product != "":
		cpes, err := client.GetCPEs(ctx, f.Product)
		if err != nil {
			return err
		}
		seen := map[string]CVE{}
		for _, cpe := range cpes {
			p := cveParams(f)
			p.Set("cpe23", cpe)
			list, err := client.GetCVEs(ctx, p)
			if err != nil {
				return err
			}
			for _, c := range list {
				seen[c.ID] = c
			}
		}
		for _, v := range seen {
			cves = append(cves, v)
		}
		if f.EPSSTop {
			sort.Slice(cves, func(i, j int) bool {
				var a, b float64
				if cves[i].EPSS != nil {
					a = *cves[i].EPSS
				}
				if cves[j].EPSS != nil {
					b = *cves[j].EPSS
				}
				return a > b
			})
		}
	}

	if f.Limit > 0 && len(cves) > f.Limit {
		cves = cves[:f.Limit]
	}

	if f.CVEJSON {
		enc := json.NewEncoder(os.Stdout)
		if f.Pretty {
			enc.SetIndent("", "  ")
		}
		return enc.Encode(cves)
	}

	for _, c := range cves {
		cvss := "-"
		if c.CVSS != nil {
			cvss = fmt.Sprintf("%.1f", *c.CVSS)
		}
		epss := "-"
		if c.EPSS != nil {
			epss = fmt.Sprintf("%.5f", *c.EPSS)
		}
		sum := ""
		if c.Summary != nil {
			sum = *c.Summary
		}
		line := []string{
			c.ID,
			cvss,
			epss,
			c.PublishedTime.Format("2006-01-02"),
			boolToStr(c.KEV),
			truncate(sum, 120),
		}
		fmt.Println(strings.Join(line, "\t"))
	}
	return nil
}

func boolToStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}
