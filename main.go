package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var userAgents = []string{
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) Firefox/122.0",
	"Mozilla/5.0 (X11; Ubuntu; Linux x86_64) Firefox/122.0",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15) Firefox/122.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) Edge/120.0.2210.133",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Edge/120.0.2210.133",
	"Mozilla/5.0 (X11; Linux x86_64) Edge/120.0.2210.133",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.2210.133",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 17_2_1 like Mac OS X) Version/17.2 Mobile/15E148 Safari/604.1",
	"Mozilla/5.0 (iPad; CPU OS 17_2_1 like Mac OS X) Version/17.2 Mobile/15E148 Safari/604.1",
}

func main() {
	rand.Seed(time.Now().UnixNano())
	cfg, cveFlags, err := parseFlags(os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}

	if cveFlags.anyCVEQuery() {
		if err := runCVEQuery(cveFlags); err != nil {
			log.Fatal(err)
		}
		return
	}

	ips, err := fetchIPs(cfg.Query, !cfg.NoUARotate)
	if err != nil {
		log.Fatal(err)
	}

	results := make([]Result, 0, len(ips))
	for _, ip := range ips {
		r := Result{IP: ip}
		if cfg.Domains || cfg.WithDomains || cfg.JSON || cfg.HasDomain {
			r.Domain = resolveDomain(ip)
		}
		if cfg.Ports || cfg.JSON || cveFlags.JoinCVEs || cfg.HTTPX {
		if cfg.Ports || cfg.JSON || cveFlags.JoinCVEs {
			ports, cpes := fetchPorts(ip)
			r.Ports = ports
			r.CPEs = cpes
			if len(cpes) > 0 {
				r.Product, r.Version = productFromCPE(cpes[0])
			}
		}
		if cfg.ASN != "" || cfg.Country != "" || cfg.Geo || cfg.JSON || cveFlags.JoinCVEs {
			org, asn, country := fetchIPInfo(ip)
			r.Org = org
			r.ASN = asn
			r.Country = country
		}
		results = append(results, r)
	}

	results = filterResults(results, cfg)

	if cveFlags.JoinCVEs {
		for i := range results {
			rec := IPEnrich{
				IP:      results[i].IP,
				ASN:     results[i].ASN,
				Country: results[i].Country,
				CPEs:    results[i].CPEs,
				Product: results[i].Product,
				Version: results[i].Version,
			}
			if len(results[i].Ports) > 0 {
				rec.Port = results[i].Ports[0]
			}
			if err := enrichWithCVEs(&rec, cveFlags); err == nil {
				results[i].TopCVE = rec.TopCVE
			}
		}
	}

	if cfg.Limit > 0 && len(results) > cfg.Limit {
		results = results[:cfg.Limit]
	}

	if cfg.Shuffle {
		rand.Shuffle(len(results), func(i, j int) { results[i], results[j] = results[j], results[i] })
	}

	if cfg.HTTPX {
		if err := runHTTPX(results); err != nil {
			log.Printf("httpx: %v", err)
		}
	}

	output := buildOutput(results, cfg, cveFlags)
	if cfg.SaveFile != "" {
		if err := os.WriteFile(cfg.SaveFile, []byte(output), 0644); err != nil {
			log.Fatalf("save: %v", err)
		}
	}
	fmt.Print(output)
}

// fetchIPs queries Shodan for IPs matching query.
func fetchIPs(query string, rotate bool) ([]string, error) {
	encodedQuery := url.QueryEscape(query)
	baseURL := fmt.Sprintf("https://www.shodan.io/search/facet?query=%s&facet=ip", encodedQuery)

	ua := userAgents[0]
	if rotate {
		ua = userAgents[rand.Intn(len(userAgents))]
	}

	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest("GET", baseURL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", ua)
	req.Header.Set("Accept", "text/html,application/xhtml+xml")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	ipRegex := regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b`)
	ips := ipRegex.FindAllString(string(body), -1)

	filtered := make([]string, 0, len(ips))
	for _, ip := range ips {
		if !isPrivateOrReservedIP(ip) {
			filtered = append(filtered, ip)
		}
	}

	return removeDuplicates(filtered), nil
}

func buildOutput(results []Result, cfg Config, cve *CVEFlags) string {
	var sb strings.Builder
	switch {
	case cve != nil && cve.JoinCVEs:
		for _, r := range results {
			fields := []string{r.IP}
			if len(r.Ports) > 0 {
				fields = append(fields, strconv.Itoa(r.Ports[0]))
			} else {
				fields = append(fields, "")
			}
			fields = append(fields, r.Product, r.Version, r.ASN, r.Country)
			if r.TopCVE != nil {
				cvss := "-"
				epss := "-"
				if r.TopCVE.CVSS != nil {
					cvss = fmt.Sprintf("%.1f", *r.TopCVE.CVSS)
				}
				if r.TopCVE.EPSS != nil {
					epss = fmt.Sprintf("%.5f", *r.TopCVE.EPSS)
				}
				fields = append(fields, r.TopCVE.ID, cvss, epss, boolToStr(r.TopCVE.KEV))
			} else {
				fields = append(fields, "", "", "", "")
			}
			if cfg.HTTPX {
				fields = append(fields, r.Title, r.Screenshot)
			}

			sb.WriteString(strings.Join(fields, "\t") + "\n")
		}
	case cfg.JSON:
		enc := json.NewEncoder(&sb)
		enc.SetIndent("", "  ")
		enc.Encode(results)
	case cfg.WithDomains:
		for _, r := range results {
			fields := []string{r.IP, r.Domain}
			if cfg.Geo && r.Country != "" {
				fields = append(fields, r.Country)
			}
			if cfg.Ports && len(r.Ports) > 0 {
				fields = append(fields, intsToCSV(r.Ports))
			}
			if cfg.HTTPX {
				fields = append(fields, r.Title, r.Screenshot)
			}

			sb.WriteString(strings.Join(fields, ",") + "\n")
		}
	case cfg.Domains:
		for _, r := range results {
			if r.Domain != "" {
				sb.WriteString(r.Domain + "\n")
			}
		}
	default:
		for _, r := range results {
			parts := []string{r.IP}
			if cfg.Ports && len(r.Ports) > 0 {
				parts = append(parts, intsToCSV(r.Ports))
			}
			if cfg.Geo && r.Country != "" {
				parts = append(parts, r.Country)
			}
			if cfg.HTTPX {
				parts = append(parts, r.Title, r.Screenshot)
			}

			sb.WriteString(strings.Join(parts, "\t") + "\n")
		}
	}
	return sb.String()
}

func intsToCSV(ints []int) string {
	if len(ints) == 0 {
		return ""
	}
	var sb strings.Builder
	for i, n := range ints {
		if i > 0 {
			sb.WriteByte(',')
		}
		sb.WriteString(strconv.Itoa(n))
	}
	return sb.String()
}

func isPrivateOrReservedIP(ip string) bool {
	privateRanges := []string{
		"^0\\.", "^127\\.", "^169\\.254\\.",
		"^172\\.(1[6-9]|2[0-9]|3[0-1])\\.",
		"^192\\.168\\.", "^10\\.",
		"^224\\.", "^240\\.", "^281\\.", "^292\\.",
	}

	for _, pattern := range privateRanges {
		match, _ := regexp.MatchString(pattern, ip)
		if match {
			return true
		}
	}
	return false
}

func removeDuplicates(slice []string) []string {
	keys := make(map[string]bool)
	list := []string{}
	for _, entry := range slice {
		if !keys[entry] {
			keys[entry] = true
			list = append(list, entry)
		}
	}
	return list
}
