package main

import (
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"time"
)

// resolveDomain performs a reverse DNS lookup for the IP with timeout and validation.
func resolveDomain(ip string) string {
	// Validate IP format first
	if net.ParseIP(ip) == nil {
		return ""
	}
	
	names, err := net.LookupAddr(ip)
	if err != nil || len(names) == 0 {
		return ""
	}
	
	// Clean and validate the domain name
	domain := strings.TrimSuffix(names[0], ".")
	domain = strings.ToLower(domain)
	
	// Basic domain validation
	if len(domain) == 0 || len(domain) > 253 {
		return ""
	}
	
	return domain
}

// Shared HTTP client with optimized settings for better performance
var sharedClient = &http.Client{
	Timeout: 8 * time.Second, // Reduced timeout for faster failures
	Transport: &http.Transport{
		MaxIdleConns:          200,  // Increased for better connection reuse
		MaxIdleConnsPerHost:   20,   // Increased per-host connections
		IdleConnTimeout:       120 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,  // Faster TLS handshake timeout
		ResponseHeaderTimeout: 6 * time.Second,  // Faster response timeout
		DisableKeepAlives:     false,            // Enable keep-alives for reuse
	},
}

// fetchIPInfo queries ip-api.com for ASN, organization and country data with retry logic and validation.
func fetchIPInfo(ip string) (org, asn, country string) {
	// Validate IP format first
	if net.ParseIP(ip) == nil {
		return "", "", ""
	}
	
	url := "http://ip-api.com/json/" + ip + "?fields=org,as,countryCode,status"
	
	// Simple retry for this endpoint
	for attempt := 0; attempt < 2; attempt++ {
		resp, err := sharedClient.Get(url)
		if err != nil {
			if attempt == 0 {
				time.Sleep(1 * time.Second)
				continue
			}
			return "", "", ""
		}
		defer resp.Body.Close()
		
		// Check HTTP status
		if resp.StatusCode != http.StatusOK {
			if attempt == 0 {
				time.Sleep(1 * time.Second)
				continue
			}
			return "", "", ""
		}
		
		var data struct {
			Status      string `json:"status"`
			Org         string `json:"org"`
			AS          string `json:"as"`
			CountryCode string `json:"countryCode"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
			if attempt == 0 {
				time.Sleep(1 * time.Second)
				continue
			}
			return "", "", ""
		}
		
		// Check API response status
		if data.Status != "success" {
			if attempt == 0 {
				time.Sleep(1 * time.Second)
				continue
			}
			return "", "", ""
		}
		
		// Extract ASN from AS field (format: "AS#### Organization Name")
		asn := ""
		if data.AS != "" {
			parts := strings.Fields(data.AS)
			if len(parts) > 0 && strings.HasPrefix(parts[0], "AS") {
				asn = parts[0]
			}
		}
		
		// Validate country code format (should be 2 letters)
		country := strings.ToUpper(data.CountryCode)
		if len(country) != 2 {
			country = ""
		}
		
		return data.Org, asn, country
	}
	return "", "", ""
}

// fetchPorts retrieves open ports and CPEs from Shodan's InternetDB service with retry logic and validation.
func fetchPorts(ip string) ([]int, []string) {
	// Validate IP format first
	if net.ParseIP(ip) == nil {
		return nil, nil
	}
	
	// Simple retry for this endpoint
	for attempt := 0; attempt < 2; attempt++ {
		resp, err := sharedClient.Get("https://internetdb.shodan.io/" + ip)
		if err != nil {
			if attempt == 0 {
				time.Sleep(1 * time.Second)
				continue
			}
			return nil, nil
		}
		defer resp.Body.Close()
		
		// Check HTTP status - 404 is normal for IPs not in Shodan
		if resp.StatusCode == http.StatusNotFound {
			return nil, nil
		}
		if resp.StatusCode != http.StatusOK {
			if attempt == 0 {
				time.Sleep(1 * time.Second)
				continue
			}
			return nil, nil
		}
		
		var data struct {
			Ports []int    `json:"ports"`
			CPEs  []string `json:"cpes"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
			if attempt == 0 {
				time.Sleep(1 * time.Second)
				continue
			}
			return nil, nil
		}
		
		// Validate port numbers
		var validPorts []int
		for _, port := range data.Ports {
			if port > 0 && port <= 65535 {
				validPorts = append(validPorts, port)
			}
		}
		
		// Basic CPE validation
		var validCPEs []string
		for _, cpe := range data.CPEs {
			if strings.HasPrefix(cpe, "cpe:") && len(cpe) > 10 {
				validCPEs = append(validCPEs, cpe)
			}
		}
		
		return validPorts, validCPEs
	}
	return nil, nil
}

// fetchPortsWithRetry wraps fetchPorts with retry logic
func fetchPortsWithRetry(ip string, maxRetries int) ([]int, []string) {
	for attempt := 0; attempt < maxRetries; attempt++ {
		ports, cpes := fetchPorts(ip)
		if ports != nil || cpes != nil {
			return ports, cpes
		}
		if attempt < maxRetries-1 {
			time.Sleep(time.Duration(attempt+1) * time.Second)
		}
	}
	return nil, nil
}

// fetchIPInfoWithRetry wraps fetchIPInfo with retry logic  
func fetchIPInfoWithRetry(ip string, maxRetries int) (string, string, string) {
	for attempt := 0; attempt < maxRetries; attempt++ {
		org, asn, country := fetchIPInfo(ip)
		if org != "" || asn != "" || country != "" {
			return org, asn, country
		}
		if attempt < maxRetries-1 {
			time.Sleep(time.Duration(attempt+1) * time.Second)
		}
	}
	return "", "", ""
}
