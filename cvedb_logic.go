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
	// New filtering parameters
	if f.MinCVSS > 0 {
		q.Set("min_cvss", fmt.Sprintf("%.1f", f.MinCVSS))
	}
	if f.MaxCVSS < 10 {
		q.Set("max_cvss", fmt.Sprintf("%.1f", f.MaxCVSS))
	}
	if f.VulnSearch != "" {
		q.Set("search", f.VulnSearch)
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

	// Apply client-side filtering for new features
	cves = filterCVEs(cves, f)
	
	if f.StatsOnly {
		return printCVEStats(cves)
	}
	
	if f.Limit > 0 && len(cves) > f.Limit {
		cves = cves[:f.Limit]
	}

	// Export options
	if f.ExportCSV {
		return exportCVEsToCSV(cves, f)
	}
	if f.ExportHTML {
		return exportCVEsToHTML(cves, f)
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

// filterCVEs applies client-side filtering for enhanced search
func filterCVEs(cves []CVE, f *CVEFlags) []CVE {
	var filtered []CVE
	for _, cve := range cves {
		// CVSS filtering
		if f.MinCVSS > 0 && (cve.CVSS == nil || *cve.CVSS < f.MinCVSS) {
			continue
		}
		if f.MaxCVSS < 10 && (cve.CVSS != nil && *cve.CVSS > f.MaxCVSS) {
			continue
		}
		
		// EPSS filtering
		if f.MinEPSS > 0 && (cve.EPSS == nil || *cve.EPSS < f.MinEPSS) {
			continue
		}
		if f.MaxEPSS < 1.0 && (cve.EPSS != nil && *cve.EPSS > f.MaxEPSS) {
			continue
		}
		
		// Severity filtering
		if f.Severity != "" && !matchesSeverity(cve, f.Severity) {
			continue
		}
		
		// Description search (client-side if not handled by API)
		if f.VulnSearch != "" && cve.Summary != nil {
			if !strings.Contains(strings.ToLower(*cve.Summary), strings.ToLower(f.VulnSearch)) {
				continue
			}
		}
		
		filtered = append(filtered, cve)
	}
	return filtered
}

// matchesSeverity checks if CVE matches severity level
func matchesSeverity(cve CVE, severity string) bool {
	if cve.CVSS == nil {
		return false
	}
	cvss := *cve.CVSS
	switch strings.ToLower(severity) {
	case "low":
		return cvss >= 0.1 && cvss <= 3.9
	case "medium":
		return cvss >= 4.0 && cvss <= 6.9
	case "high":
		return cvss >= 7.0 && cvss <= 8.9
	case "critical":
		return cvss >= 9.0 && cvss <= 10.0
	default:
		return true
	}
}

// printCVEStats prints vulnerability statistics
func printCVEStats(cves []CVE) error {
	total := len(cves)
	kev := 0
	critical := 0
	high := 0
	medium := 0
	low := 0
	var totalCVSS, totalEPSS float64
	cvssCount, epssCount := 0, 0
	
	for _, cve := range cves {
		if cve.KEV {
			kev++
		}
		if cve.CVSS != nil {
			cvss := *cve.CVSS
			totalCVSS += cvss
			cvssCount++
			switch {
			case cvss >= 9.0:
				critical++
			case cvss >= 7.0:
				high++
			case cvss >= 4.0:
				medium++
			default:
				low++
			}
		}
		if cve.EPSS != nil {
			totalEPSS += *cve.EPSS
			epssCount++
		}
	}
	
	fmt.Printf("CVE Statistics:\n")
	fmt.Printf("Total CVEs: %d\n", total)
	fmt.Printf("KEV (Known Exploited): %d (%.1f%%)\n", kev, float64(kev)/float64(total)*100)
	fmt.Printf("\nSeverity Distribution:\n")
	fmt.Printf("  Critical (9.0-10.0): %d (%.1f%%)\n", critical, float64(critical)/float64(total)*100)
	fmt.Printf("  High (7.0-8.9): %d (%.1f%%)\n", high, float64(high)/float64(total)*100)
	fmt.Printf("  Medium (4.0-6.9): %d (%.1f%%)\n", medium, float64(medium)/float64(total)*100)
	fmt.Printf("  Low (0.1-3.9): %d (%.1f%%)\n", low, float64(low)/float64(total)*100)
	
	if cvssCount > 0 {
		fmt.Printf("\nCVSS Average: %.2f\n", totalCVSS/float64(cvssCount))
	}
	if epssCount > 0 {
		fmt.Printf("EPSS Average: %.5f\n", totalEPSS/float64(epssCount))
	}
	return nil
}

// exportCVEsToCSV exports CVEs to CSV format
func exportCVEsToCSV(cves []CVE, f *CVEFlags) error {
	filename := fmt.Sprintf("cves_%s.csv", time.Now().Format("20060102_150405"))
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()
	
	// CSV Header
	header := "CVE_ID,CVSS,EPSS,KEV,Published,Summary"
	if f.ShowRefs {
		header += ",References"
	}
	fmt.Fprintln(file, header)
	
	// CSV Data
	for _, cve := range cves {
		cvss := "-"
		if cve.CVSS != nil {
			cvss = fmt.Sprintf("%.1f", *cve.CVSS)
		}
		epss := "-"
		if cve.EPSS != nil {
			epss = fmt.Sprintf("%.5f", *cve.EPSS)
		}
		summary := ""
		if cve.Summary != nil {
			summary = strings.ReplaceAll(*cve.Summary, ",", ";")
		}
		
		line := fmt.Sprintf("%s,%s,%s,%s,%s,\"%s\"",
			cve.ID, cvss, epss, boolToStr(cve.KEV),
			cve.PublishedTime.Format("2006-01-02"), summary)
		
		if f.ShowRefs {
			refs := strings.Join(cve.References, "; ")
			line += fmt.Sprintf(",\"%s\"", refs)
		}
		
		fmt.Fprintln(file, line)
	}
	
	fmt.Printf("CVEs exported to %s\n", filename)
	return nil
}

// exportCVEsToHTML exports CVEs to HTML report
func exportCVEsToHTML(cves []CVE, f *CVEFlags) error {
	filename := fmt.Sprintf("cves_report_%s.html", time.Now().Format("20060102_150405"))
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()
	
	// HTML Template
	htmlContent := `<!DOCTYPE html>
<html><head>
<title>CVE Report</title>
<style>
body { font-family: Arial, sans-serif; margin: 20px; }
table { border-collapse: collapse; width: 100%; }
th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
th { background-color: #f2f2f2; }
.critical { background-color: #ffebee; }
.high { background-color: #fff3e0; }
.medium { background-color: #fff8e1; }
.low { background-color: #e8f5e8; }
.kev { font-weight: bold; color: #d32f2f; }
</style>
</head><body>
<h1>CVE Vulnerability Report</h1>
<p>Generated: ` + time.Now().Format("2006-01-02 15:04:05") + `</p>
<p>Total CVEs: ` + fmt.Sprintf("%d", len(cves)) + `</p>
<table>
<tr><th>CVE ID</th><th>CVSS</th><th>EPSS</th><th>KEV</th><th>Published</th><th>Summary</th></tr>
`
	
	for _, cve := range cves {
		cvss := "-"
		rowClass := ""
		if cve.CVSS != nil {
			cvss = fmt.Sprintf("%.1f", *cve.CVSS)
			switch {
			case *cve.CVSS >= 9.0:
				rowClass = "critical"
			case *cve.CVSS >= 7.0:
				rowClass = "high"
			case *cve.CVSS >= 4.0:
				rowClass = "medium"
			default:
				rowClass = "low"
			}
		}
		
		epss := "-"
		if cve.EPSS != nil {
			epss = fmt.Sprintf("%.5f", *cve.EPSS)
		}
		
		summary := "No summary available"
		if cve.Summary != nil {
			summary = *cve.Summary
		}
		
		kevClass := ""
		kevText := "No"
		if cve.KEV {
			kevClass = " kev"
			kevText = "YES"
		}
		
		htmlContent += fmt.Sprintf(`<tr class="%s"><td>%s</td><td>%s</td><td>%s</td><td class="%s">%s</td><td>%s</td><td>%s</td></tr>`,
			rowClass, cve.ID, cvss, epss, kevClass, kevText,
			cve.PublishedTime.Format("2006-01-02"), summary) + "\n"
	}
	
	htmlContent += `</table>
</body></html>`
	
	_, err = file.WriteString(htmlContent)
	if err != nil {
		return err
	}
	
	fmt.Printf("HTML report exported to %s\n", filename)
	return nil
}
