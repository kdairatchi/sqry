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
	"sync"
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

func getUserAgent(rotate bool) string {
	if rotate {
		return userAgents[rand.Intn(len(userAgents))]
	}
	return userAgents[0]
}

func main() {
	rand.Seed(time.Now().UnixNano())

	// Clear expired cache entries on startup for better performance
	clearExpiredCache()
	
	// Simple argument parsing - restore original simplicity but allow enhanced features
	cfg, cveFlags, err := parseFlags(os.Args[1:])
	if err != nil {
		if strings.Contains(err.Error(), "version info displayed") {
			return // Clean exit for version
		}
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	// Show banner for interactive sessions
	if !cfg.JSON && cfg.SaveFile == "" && !cfg.Quiet {
		printBanner()
	}

	// Dry run mode
	if cfg.DryRun {
		printDryRunInfo(cfg, cveFlags)
		return
	}

	// Handle CVE-only queries
	if cveFlags.anyCVEQuery() {
		if err := runCVEQuery(cveFlags); err != nil {
			log.Fatal(err)
		}
		return
	}

	// Core functionality: fetch IPs from Shodan with caching and rate limiting
	start := time.Now()
	var progress *ProgressIndicator
	if !cfg.Quiet {
		progress = NewProgress("🔍 Fetching IPs from Shodan...")
	}
	
	// Try cache first if enabled
	var ips []string
	cacheKey := getCacheKey(cfg.Query)
	if !cfg.NoCache {
		if cached, found := cacheGet(cacheKey); found {
			if cachedIPs, ok := cached.([]string); ok {
				ips = cachedIPs
				if !cfg.Quiet {
					printSuccess("Using cached results")
				}
			}
		}
	}
	
	if len(ips) == 0 {
		var err error
		ips, err = fetchIPsOptimized(cfg)
		if err == nil && !cfg.NoCache {
			// Cache results for 30 minutes
			cacheSet(cacheKey, ips, 1800)
		}
		if err != nil {
			if progress != nil {
				progress.Stop()
			}
			if !cfg.Quiet {
				printError(fmt.Sprintf("Failed to fetch IPs: %v", err))
			} else {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			}
			os.Exit(1)
		}
	}
	
	if progress != nil {
		progress.Stop()
	}

	if len(ips) == 0 {
		if !cfg.Quiet {
			printWarning("No IPs found for query")
		}
		return
	}

	if !cfg.Quiet {
		printSuccess(fmt.Sprintf("Found %d unique IPs", len(ips)))
	}

	// Enhanced processing (if requested)
	var results []Result
	if cfg.Domains || cfg.WithDomains || cfg.JSON || cfg.Ports || cfg.Geo || cveFlags.JoinCVEs || cfg.HTTPX {
		if !cfg.Quiet {
			progress = NewProgress("🔬 Enriching IPs with additional data...")
		}
		results = processIPsConcurrently(ips, cfg, cveFlags)
		if progress != nil {
			progress.Stop()
		}
		
		// Show processing statistics
		if !cfg.Quiet && cfg.Verbose {
			successful := 0
			for _, r := range results {
				if r.Domain != "" || len(r.Ports) > 0 || r.Country != "" {
					successful++
				}
			}
			printInfo(fmt.Sprintf("Successfully enriched %d/%d IPs (%.1f%%)", successful, len(results), float64(successful)/float64(len(results))*100))
		}
		
		results = filterResults(results, cfg)

		if cveFlags.JoinCVEs {
			if !cfg.Quiet {
				progress = NewProgress("🛡️ Analyzing CVE vulnerabilities...")
			}
			enrichResultsWithCVEs(results, cveFlags)
			if progress != nil {
				progress.Stop()
			}
		}

		if cfg.HTTPX {
			if !cfg.Quiet {
				progress = NewProgress("🌐 Running HTTP probes...")
			}
			if err := runHTTPX(results); err != nil {
				if !cfg.Quiet {
					printWarning(fmt.Sprintf("httpx: %v", err))
				}
			}
			if progress != nil {
				progress.Stop()
			}
		}
	} else {
		// Simple mode: convert IPs to results for uniform handling
		results = make([]Result, len(ips))
		for i, ip := range ips {
			results[i] = Result{IP: ip}
		}
	}

	// Apply limits and shuffling with better performance
	if cfg.MaxResults > 0 && len(results) > cfg.MaxResults {
		if !cfg.Quiet {
			printWarning(fmt.Sprintf("Truncating results from %d to %d (use --max-results to adjust)", len(results), cfg.MaxResults))
		}
		results = results[:cfg.MaxResults]
	}
	
	if cfg.Limit > 0 && len(results) > cfg.Limit {
		results = results[:cfg.Limit]
	}

	if cfg.Shuffle {
		rand.Shuffle(len(results), func(i, j int) { results[i], results[j] = results[j], results[i] })
	}

	// Generate and save output
	output := buildOutput(results, cfg, cveFlags)
	if cfg.SaveFile != "" {
		if err := os.WriteFile(cfg.SaveFile, []byte(output), 0644); err != nil {
			fmt.Fprintf(os.Stderr, "Error saving file: %v\n", err)
			os.Exit(1)
		}
		if !cfg.Quiet {
			printSuccess(fmt.Sprintf("Results saved to %s", cfg.SaveFile))
		}
	}

	// Show stats and output
	if !cfg.Quiet {
		duration := time.Since(start)
		printStats(len(results), duration)
	}

	fmt.Print(output)
}

// processIPsConcurrently processes IPs with optimized concurrent goroutines and rate limiting
func processIPsConcurrently(ips []string, cfg Config, cveFlags *CVEFlags) []Result {
	results := make([]Result, len(ips))
	var wg sync.WaitGroup
	workers := cfg.Workers
	if workers <= 0 {
		workers = 10 // Default fallback
	}
	if len(ips) < workers {
		workers = len(ips)
	}

	// Rate limiting setup for worker goroutines
	var rateLimitChan chan struct{}
	if cfg.RateLimit > 0 {
		rateLimitChan = make(chan struct{}, cfg.RateLimit)
		// Fill the channel initially
		for i := 0; i < cfg.RateLimit; i++ {
			rateLimitChan <- struct{}{}
		}
		// Refill the channel periodically
		go func() {
			ticker := time.NewTicker(time.Second)
			defer ticker.Stop()
			for range ticker.C {
				for i := 0; i < cfg.RateLimit; i++ {
					select {
					case rateLimitChan <- struct{}{}:
					default:
					}
				}
			}
		}()
	}

	ipChan := make(chan struct{ index int; ip string }, len(ips))

	// Start workers
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for item := range ipChan {
				// Rate limiting if configured
				if rateLimitChan != nil {
					<-rateLimitChan // Wait for rate limit token
				}
				
				r := Result{IP: item.ip}
				if cfg.Domains || cfg.WithDomains || cfg.JSON || cfg.HasDomain {
					r.Domain = resolveDomain(item.ip)
				}
				if cfg.Ports || cfg.JSON || cveFlags.JoinCVEs || cfg.HTTPX {
					ports, cpes := fetchPortsWithRetry(item.ip, cfg.RetryAttempts)
					r.Ports = ports
					r.CPEs = cpes
					if len(cpes) > 0 {
						r.Product, r.Version = productFromCPE(cpes[0])
					}
				}
				if cfg.ASN != "" || cfg.Country != "" || cfg.Geo || cfg.JSON || cveFlags.JoinCVEs {
					org, asn, country := fetchIPInfoWithRetry(item.ip, cfg.RetryAttempts)
					r.Org = org
					r.ASN = asn
					r.Country = country
				}
				results[item.index] = r
			}
		}()
	}

	// Send work to workers
	for i, ip := range ips {
		ipChan <- struct{ index int; ip string }{i, ip}
	}
	close(ipChan)

	wg.Wait()
	return results
}

// enrichResultsWithCVEs enriches results with CVE data concurrently
func enrichResultsWithCVEs(results []Result, cveFlags *CVEFlags) {
	var wg sync.WaitGroup
	workers := 5 // Fewer workers for CVE API calls to avoid rate limits
	if len(results) < workers {
		workers = len(results)
	}

	resultChan := make(chan int, len(results))

	// Start workers
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range resultChan {
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
		}()
	}

	// Send work to workers
	for i := range results {
		resultChan <- i
	}
	close(resultChan)

	wg.Wait()
}

// fetchIPsSimple queries Shodan for IPs matching query - enhanced but reliable version
func fetchIPsSimple(query string, rotate bool, timeoutSecs int) ([]string, error) {
	encodedQuery := url.QueryEscape(query)

	// Enhanced retry logic - try both facet and regular search endpoints
	maxRetries := 2
	endpoints := []string{
		fmt.Sprintf("https://www.shodan.io/search/facet?query=%s&facet=ip", encodedQuery),
		fmt.Sprintf("https://www.shodan.io/search?query=%s", encodedQuery),
	}

	for attempt := 0; attempt < maxRetries; attempt++ {
		for _, endpoint := range endpoints {
			ua := getUserAgent(rotate)
			
			client := &http.Client{
				Timeout: time.Duration(timeoutSecs) * time.Second,
				Transport: &http.Transport{
					MaxIdleConns:          100,
					MaxIdleConnsPerHost:   10,
					IdleConnTimeout:       90 * time.Second,
					TLSHandshakeTimeout:   10 * time.Second,
					ResponseHeaderTimeout: 30 * time.Second,
				},
			}
			
			req, err := http.NewRequest("GET", endpoint, nil)
			if err != nil {
				continue
			}

			req.Header.Set("User-Agent", ua)
			req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
			req.Header.Set("Accept-Language", "en-US,en;q=0.9")
			req.Header.Set("DNT", "1")
			req.Header.Set("Connection", "keep-alive")
			req.Header.Set("Upgrade-Insecure-Requests", "1")

			resp, err := client.Do(req)
			if err != nil {
				if attempt == maxRetries-1 {
					return nil, fmt.Errorf("failed to fetch from Shodan: %w", err)
				}
				time.Sleep(time.Duration(attempt+1) * time.Second)
				continue
			}
			defer resp.Body.Close()

			if resp.StatusCode == http.StatusTooManyRequests {
				if attempt < maxRetries-1 {
					time.Sleep(time.Duration(attempt+2) * time.Second)
					continue
				}
				return nil, fmt.Errorf("rate limited by Shodan - try again later")
			}

			if resp.StatusCode != http.StatusOK {
				if attempt < maxRetries-1 {
					continue
				}
				return nil, fmt.Errorf("Shodan returned status %d", resp.StatusCode)
			}

			body, err := io.ReadAll(resp.Body)
			if err != nil {
				if attempt < maxRetries-1 {
					continue
				}
				return nil, fmt.Errorf("failed to read response: %w", err)
			}

			// Enhanced IP extraction with validation
			ipRegex := regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b`)
			ips := ipRegex.FindAllString(string(body), -1)

			// Filter private/reserved IPs and validate
			uniqueIPs := make(map[string]bool)
			var filtered []string
			for _, ip := range ips {
				if !isPrivateOrReservedIP(ip) && isValidPublicIP(ip) && !uniqueIPs[ip] {
					uniqueIPs[ip] = true
					filtered = append(filtered, ip)
				}
			}

			// Log extraction stats if verbose
			if len(ips) > 0 && len(filtered) != len(ips) {
				// Only log if we filtered out some IPs
			}

			if len(filtered) > 0 {
				return filtered, nil
			}
		}
	}

	return nil, fmt.Errorf("no valid public IPs found in Shodan response")
}

// fetchIPs queries Shodan for IPs matching query with robust retry logic and timeout handling.
func fetchIPs(query string, rotate bool, timeoutSecs int) ([]string, error) {
	encodedQuery := url.QueryEscape(query)
	baseURL := fmt.Sprintf("https://www.shodan.io/search?query=%s", encodedQuery)

	// Retry configuration
	maxRetries := 3
	baseDelay := 2 * time.Second

	for attempt := 0; attempt <= maxRetries; attempt++ {
		ua := userAgents[0]
		if rotate {
			ua = userAgents[rand.Intn(len(userAgents))]
		}

		// Use configurable timeout with progressive increase
		timeout := time.Duration(timeoutSecs) * time.Second + time.Duration(attempt)*15*time.Second
		
		client := &http.Client{
			Timeout: timeout,
			Transport: &http.Transport{
				MaxIdleConns:          100,
				MaxIdleConnsPerHost:   10,
				IdleConnTimeout:       90 * time.Second,
				TLSHandshakeTimeout:   10 * time.Second,
				ResponseHeaderTimeout: 30 * time.Second,
			},
		}
		
		req, err := http.NewRequest("GET", baseURL, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to create request: %w", err)
		}

		req.Header.Set("User-Agent", ua)
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
		req.Header.Set("Accept-Language", "en-US,en;q=0.9")
		req.Header.Set("DNT", "1")
		req.Header.Set("Connection", "keep-alive")
		req.Header.Set("Upgrade-Insecure-Requests", "1")

		if attempt > 0 {
			fmt.Fprintf(os.Stderr, "Retrying Shodan request (attempt %d/%d, timeout: %v)...\n", attempt+1, maxRetries+1, timeout)
		} else if timeoutSecs > 30 {
			fmt.Fprintf(os.Stderr, "Fetching from Shodan (timeout: %v, this may take a while)...\n", timeout)
		}

		resp, err := client.Do(req)
		if err != nil {
			if attempt < maxRetries {
				// Exponential backoff with jitter
				delay := baseDelay * time.Duration(1<<attempt) + time.Duration(rand.Intn(1000))*time.Millisecond
				if !rotate { // Only print debug if not in quiet mode
					fmt.Fprintf(os.Stderr, "Attempt %d failed: %v, retrying in %v...\n", attempt+1, err, delay.Round(time.Millisecond))
				}
				time.Sleep(delay)
				continue
			}
			return nil, fmt.Errorf("failed to fetch from Shodan after %d attempts: %w (consider increasing --shodan-timeout from %ds)", maxRetries+1, err, timeoutSecs)
		}
		defer resp.Body.Close()

		// Handle rate limiting and server errors with retry
		if resp.StatusCode == http.StatusTooManyRequests {
			if attempt < maxRetries {
				delay := baseDelay * time.Duration(1<<(attempt+1)) + time.Duration(rand.Intn(2000))*time.Millisecond
				if !rotate { // Only print debug if not in quiet mode
					fmt.Fprintf(os.Stderr, "Rate limited by Shodan, waiting %v before retry...\n", delay.Round(time.Millisecond))
				}
				time.Sleep(delay)
				continue
			}
			return nil, fmt.Errorf("Shodan rate limited after %d attempts - try again later or use different queries", maxRetries+1)
		}
		if resp.StatusCode >= 500 {
			if attempt < maxRetries {
				delay := baseDelay * time.Duration(1<<attempt) + time.Duration(rand.Intn(1000))*time.Millisecond
				time.Sleep(delay)
				continue
			}
			return nil, fmt.Errorf("Shodan server error %d: %s after %d attempts", resp.StatusCode, resp.Status, maxRetries+1)
		}

		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("Shodan returned status %d: %s", resp.StatusCode, resp.Status)
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			if attempt < maxRetries {
				delay := baseDelay * time.Duration(1<<attempt)
				time.Sleep(delay)
				continue
			}
			return nil, fmt.Errorf("failed to read response body after %d attempts: %w", maxRetries+1, err)
		}

		ipRegex := regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b`)
		ips := ipRegex.FindAllString(string(body), -1)

		if len(ips) == 0 {
			if attempt < maxRetries {
				delay := baseDelay * time.Duration(1<<attempt)
				time.Sleep(delay)
				continue
			}
			return nil, fmt.Errorf("no IPs found in Shodan response after %d attempts - check your query", maxRetries+1)
		}

		// Enhanced filtering: remove private/reserved IPs and validate
		uniqueIPs := make(map[string]bool)
		filtered := make([]string, 0, len(ips))
		for _, ip := range ips {
			if !isPrivateOrReservedIP(ip) && isValidPublicIP(ip) && !uniqueIPs[ip] {
				uniqueIPs[ip] = true
				filtered = append(filtered, ip)
			}
		}

		if len(filtered) == 0 {
			if attempt < maxRetries {
				delay := baseDelay * time.Duration(1<<attempt)
				time.Sleep(delay)
				continue
			}
			return nil, fmt.Errorf("no valid public IPs found in Shodan response after %d attempts", maxRetries+1)
		}

		return filtered, nil
	}

	return nil, fmt.Errorf("unexpected error: exhausted all retry attempts")
}

// Simple rate limiter using time.Sleep
var lastRequest time.Time
var requestMutex sync.Mutex

// fetchIPsOptimized is the enhanced version with rate limiting and better error handling
func fetchIPsOptimized(cfg Config) ([]string, error) {
	// Simple rate limiting without external dependencies
	if cfg.RateLimit > 0 {
		requestMutex.Lock()
		elapsed := time.Since(lastRequest)
		minInterval := time.Second / time.Duration(cfg.RateLimit)
		if elapsed < minInterval {
			time.Sleep(minInterval - elapsed)
		}
		lastRequest = time.Now()
		requestMutex.Unlock()
	}
	
	return fetchIPsSimple(cfg.Query, !cfg.NoUARotate, cfg.ShodanTimeout)
}

// printDryRunInfo shows what the tool would do without actually doing it
func printDryRunInfo(cfg Config, cve *CVEFlags) {
	printInfo("DRY RUN MODE - No actual requests will be made")
	fmt.Printf("Query: %s\n", cfg.Query)
	fmt.Printf("Workers: %d\n", cfg.Workers)
	fmt.Printf("Rate Limit: %d req/sec\n", cfg.RateLimit)
	fmt.Printf("Batch Size: %d\n", cfg.BatchSize)
	fmt.Printf("Max Results: %d\n", cfg.MaxResults)
	fmt.Printf("Timeout: %ds\n", cfg.ShodanTimeout)
	if cfg.Domains {
		fmt.Println("Would lookup domains")
	}
	if cfg.Ports {
		fmt.Println("Would fetch port information")
	}
	if cfg.Geo {
		fmt.Println("Would fetch geo information")
	}
	if cfg.HTTPX {
		fmt.Println("Would run httpx probes")
	}
	if cve != nil && cve.JoinCVEs {
		fmt.Println("Would enrich with CVE data")
	}
}

func buildOutput(results []Result, cfg Config, cve *CVEFlags) string {
	var sb strings.Builder
	switch {
	case cve != nil && cve.JoinCVEs:
		if !isTerminal() || cfg.SaveFile != "" {
			// Tab-separated for scripts/files
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
		} else {
			// Pretty table for terminal
			headers := []string{"IP", "Port", "Product", "Version", "ASN", "Country", "CVE ID", "CVSS", "EPSS", "KEV"}
			if cfg.HTTPX {
				headers = append(headers, "Title", "Screenshot")
			}
			var rows [][]string
			for _, r := range results {
				row := []string{r.IP}
				if len(r.Ports) > 0 {
					row = append(row, strconv.Itoa(r.Ports[0]))
				} else {
					row = append(row, "-")
				}
				row = append(row, truncateString(r.Product, 12), truncateString(r.Version, 10), r.ASN, r.Country)
				if r.TopCVE != nil {
					cvss := "-"
					epss := "-"
					if r.TopCVE.CVSS != nil {
						cvss = fmt.Sprintf("%.1f", *r.TopCVE.CVSS)
					}
					if r.TopCVE.EPSS != nil {
						epss = fmt.Sprintf("%.3f", *r.TopCVE.EPSS)
					}
					kev := "No"
					if r.TopCVE.KEV {
						kev = "Yes"
					}
					row = append(row, r.TopCVE.ID, cvss, epss, kev)
				} else {
					row = append(row, "-", "-", "-", "-")
				}
				if cfg.HTTPX {
					row = append(row, truncateString(r.Title, 30), truncateString(r.Screenshot, 20))
				}
				rows = append(rows, row)
			}
			return formatTable(headers, rows)
		}
	case cfg.JSON:
		enc := json.NewEncoder(&sb)
		if isTerminal() && cfg.SaveFile == "" {
			enc.SetIndent("", "  ")
		}
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
		"^224\\.", "^240\\.", "^100\\.64\\.",
		"^255\\.", // Broadcast addresses
	}

	for _, pattern := range privateRanges {
		if matched, _ := regexp.MatchString(pattern, ip); matched {
			return true
		}
	}
	return false
}

// isValidPublicIP performs additional validation beyond regex to ensure IP is valid and public
func isValidPublicIP(ip string) bool {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return false
	}
	
	for _, part := range parts {
		if len(part) == 0 {
			return false
		}
		// Check for leading zeros (except single 0)
		if len(part) > 1 && part[0] == '0' {
			return false
		}
		// Additional check: ensure it's a valid number and in range
		val := 0
		for _, char := range part {
			if char < '0' || char > '9' {
				return false
			}
			val = val*10 + int(char-'0')
			if val > 255 {
				return false
			}
		}
	}
	return true
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

// truncateString truncates a string to maxLen, adding "..." if needed
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	if maxLen <= 3 {
		return s[:maxLen]
	}
	return s[:maxLen-3] + "..."
}

