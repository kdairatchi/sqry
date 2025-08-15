package main

import (
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"time"
)

// resolveDomain performs a reverse DNS lookup for the IP.
func resolveDomain(ip string) string {
	names, err := net.LookupAddr(ip)
	if err != nil || len(names) == 0 {
		return ""
	}
	return strings.TrimSuffix(names[0], ".")
}

// fetchIPInfo queries ip-api.com for ASN, organization and country data.
func fetchIPInfo(ip string) (org, asn, country string) {
	client := http.Client{Timeout: 5 * time.Second}
	url := "http://ip-api.com/json/" + ip + "?fields=org,as,countryCode"
	resp, err := client.Get(url)
	if err != nil {
		return "", "", ""
	}
	defer resp.Body.Close()
	var data struct {
		Org         string `json:"org"`
		AS          string `json:"as"`
		CountryCode string `json:"countryCode"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return "", "", ""
	}
	parts := strings.Fields(data.AS)
	if len(parts) > 0 {
		return data.Org, parts[0], data.CountryCode
	}
	return data.Org, "", data.CountryCode
}

// fetchPorts retrieves open ports and CPEs from Shodan's InternetDB service.
func fetchPorts(ip string) ([]int, []string) {
	client := http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get("https://internetdb.shodan.io/" + ip)
	if err != nil {
		return nil, nil
	}
	defer resp.Body.Close()
	var data struct {
		Ports []int    `json:"ports"`
		CPEs  []string `json:"cpes"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, nil
	}
	return data.Ports, data.CPEs
}
