# Sqry

Sqry is Shodan Query

`sqry` extracts IPs from Shodan searches, just the IPs you need.

## Introduction

Sqry is a lightweight command-line tool written in Go that allows users to query Shodan for IP addresses based on a specific search query. It extracts IPv4 addresses from the Shodan results, filters out private or reserved IPs, removes duplicates, and outputs the clean list of public IPs.

## Features

- Extract IPs from Shodan
- Random User-Agent rotation
- Clean, pipe-friendly output
- Zero dependencies (just bash & curl)
- Fetches data directly from Shodan's search facet endpoint
- Uses a random User-Agent for each request to avoid detection
- Extracts and validates IPv4 addresses using regex
- Filters out private, reserved, and non-routable IP ranges
- Ensures unique IP addresses in the output
- Requires a valid Shodan search query (no API key needed as it scrapes public results)

## Installation

```bash
go install github.com/Karthik-HR0/sqry@latest
```

## Usage

```text
sqry -q <query> [options]

Options:
  -q string            Shodan query
  -d, --domains        Lookup domains for each IP
      --with-domains   Output IP and domain pairs in CSV format
      --json           Output JSON with fields ip, domain, org, asn, country, port, banner, title, screenshot
      --ports          Include open ports for each IP
      --limit N        Limit results to first N IPs
      --no-ua-rotate   Disable User-Agent rotation
      --shuffle        Randomize output order
      --save FILE      Save results to a specified file
      --country XX     Filter by 2-letter country code
      --asn ASN        Filter by ASN
      --has-domain     Only include results with a resolvable domain
      --geo            Include geolocation info
      --httpx          Enrich targets with title and screenshot via httpx

CVE options (CVEDB, no key required):
      --cve ID         Fetch a specific CVE by ID
      --cpe CPE23      Fetch CVEs by CPE 2.3 string
      --product NAME   Resolve product to CPEs then fetch CVEs
      --kev            Only Known Exploited Vulnerabilities
      --epss-top       Sort by EPSS descending
      --since DATE     Filter CVEs published on/after YYYY-MM-DD
      --until DATE     Filter CVEs published on/before YYYY-MM-DD
      --cve-json       Output CVEs as JSON
      --pretty         Pretty-print JSON output
      --join-cves      Enrich IP mode with inferred CVEs via CPEs
      --timeout S      HTTP timeout for CVEDB requests (seconds)
```

## Examples

```bash
sqry -q "apache" > apache_ips.txt
sqry -q 'org:"Google LLC"'
sqry -q "port:443" | sort -u
sqry -q "apache" | xargs -I {} nmap -sV {}
sqry -q "apache" | tee ips.txt | wc -l
sqry -q "apache" | grep -v "^10\." > public_ips.txt
```

## Troubleshooting

- Check your query syntax
- Ensure you have curl installed
- Check your internet connection

Made with ❤️ by [@Karthik-HR0](https://github.com/KARTHIK-HR0)
