package main

import (
    "fmt"
    "io"
    "log"
    "math/rand"
    "net/http"
    "net/url"
    "os"
    "regexp"
   
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
    if len(os.Args) != 3 || os.Args[1] != "-q" {
        fmt.Printf("Usage: %s -q query\n", os.Args[0])
        os.Exit(1)
    }

    query := os.Args[2]
    encodedQuery := url.QueryEscape(query)
    baseURL := fmt.Sprintf("https://www.shodan.io/search/facet?query=%s&facet=ip", encodedQuery)

    // Select random user agent
    userAgent := userAgents[rand.Intn(len(userAgents))]

    // Create HTTP client and request
    client := &http.Client{}
    req, err := http.NewRequest("GET", baseURL, nil)
    if err != nil {
        log.Fatal(err)
    }

    req.Header.Set("User-Agent", userAgent)
    req.Header.Set("Accept", "text/html,application/xhtml+xml")
    req.Header.Set("Accept-Language", "en-US,en;q=0.9")

    resp, err := client.Do(req)
    if err != nil {
        log.Fatal(err)
    }
    defer resp.Body.Close()

    body, err := io.ReadAll(resp.Body)
    if err != nil {
        log.Fatal(err)
    }

    // IP regex pattern
    ipRegex := regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b`)
    ips := ipRegex.FindAllString(string(body), -1)

    // Filter out private and reserved IPs
    var filteredIPs []string
    for _, ip := range ips {
        if !isPrivateOrReservedIP(ip) {
            filteredIPs = append(filteredIPs, ip)
        }
    }

    // Remove duplicates and print
    uniqueIPs := removeDuplicates(filteredIPs)
    for _, ip := range uniqueIPs {
        fmt.Println(ip)
    }
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
        if _, value := keys[entry]; !value {
            keys[entry] = true
            list = append(list, entry)
        }
    }
    return list
}
