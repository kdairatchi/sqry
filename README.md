# sqry

sqry is a powerful command-line tool written in Go that queries Shodan and extracts IPv4 addresses with advanced CVE integration. It filters out private and reserved ranges, removes duplicates, and provides comprehensive vulnerability intelligence through CVEDB integration.

## Features

### Core Features
- **Smart IP Extraction**: Extract IPs from Shodan searches with intelligent filtering
- **Private IP Filtering**: Automatically filters out private and reserved IP ranges
- **User-Agent Rotation**: Random User-Agent rotation to avoid rate limiting
- **Multiple Output Formats**: Support for plain text, CSV, JSON, and HTML output
- **Flexible Filtering**: Filter by country, ASN, domain availability
- **Result Shuffling**: Randomize output order for better distribution
- **🚀 Optimized Performance**: Ultra-fast concurrent processing with connection pooling
- **⚡ Rate Limiting**: Built-in rate limiting with user control (no external dependencies)
- **🔄 Smart Retry**: Intelligent retry logic with exponential backoff
- **📊 Progress Indicators**: Beautiful animated progress with real-time stats
- **🎨 Professional UI**: Colorful terminal output with customizable formatting
- **💾 Atomic Caching**: Smart caching with atomic writes to prevent corruption
- **🎯 Scan Modes**: Quick scan, deep scan, and vulnerability-focused modes

### Enrichment Features
- **Domain Resolution**: Reverse DNS lookup for each IP
- **Geolocation Data**: ASN, organization, and country information via ip-api.com
- **Port Discovery**: Open ports and CPE information via Shodan InternetDB
- **HTTP Probing**: Page titles and screenshots via [httpx](https://github.com/projectdiscovery/httpx)

### Enhanced CVE Intelligence (CVEDB Integration)
- **CVE Lookup**: Search specific CVEs by ID (e.g., CVE-2021-44228)
- **CPE-based Search**: Find CVEs by CPE 2.3 strings
- **Product Search**: Resolve products to CPEs and find associated CVEs
- **KEV Filter**: Filter for Known Exploited Vulnerabilities only
- **EPSS Scoring**: Sort by EPSS (Exploit Prediction Scoring System) ratings
- **Date Filtering**: Filter CVEs by publication date ranges
- **CVE Enrichment**: Automatically enrich IP results with inferred CVEs
- **Comprehensive Scoring**: CVSS v2/v3, EPSS scores, KEV status
- **🆕 Advanced Filtering**: Filter by CVSS/EPSS ranges and severity levels
- **🆕 Export Options**: Export to CSV and HTML reports
- **🆕 Description Search**: Search within CVE descriptions and summaries
- **🆕 Statistics Mode**: Generate comprehensive vulnerability statistics
- **🆕 Enhanced Caching**: Configurable CVE cache with TTL control

## Installation

### Option 1: Go Install (Recommended)
```bash
go install github.com/kdairatchi/sqry@latest
```

### Option 2: Clone and Build
```bash
git clone https://github.com/kdairatchi/sqry.git
cd sqry
go build
./sqry --version
```

### Option 3: Download Binary
Download pre-built binaries from the [Releases](https://github.com/kdairatchi/sqry/releases) page.

### Verify Installation
```bash
sqry --version
```

## Usage
```bash
sqry -q <query> [options]
```

### Quick Start
```bash
# Basic IP extraction from Shodan
sqry -q "apache" --limit 10

# Get version information (shows beautiful banner)
sqry --version

# Quiet mode for scripts (no banner/progress)
sqry -q "nginx" --quiet --limit 5 --json

# View all options
sqry --help
```

## Command Line Options

### Core Options
| Flag | Description |
|------|-------------|
| `-q <query>` | Shodan query string (required for IP mode) |
| `-d, --domains` | Lookup domains for each IP |
| `--with-domains` | Output IP and domain pairs in CSV format |
| `--json` | Output results as JSON |
| `--ports` | Include open ports for each IP |
| `--limit N` | Limit results to first N entries |
| `--shuffle` | Randomize output order |
| `--save FILE` | Save results to specified file |
| `--no-ua-rotate` | Disable User-Agent rotation |
| `--quiet` | Suppress progress indicators and banners |
| `--verbose` | Show detailed progress information |
| `--no-cache` | Disable result caching |
| `--no-color` | Disable colored output |

### Filtering Options
| Flag | Description |
|------|-------------|
| `--country XX` | Filter by 2-letter country code |
| `--asn ASN` | Filter by ASN number |
| `--has-domain` | Only include IPs with resolvable domains |
| `--geo` | Include geolocation information |

### Performance & Control Options
| Flag | Description |
|------|-------------|
| `--rate-limit N` | Rate limit: requests per second (0 = no limit) |
| `--retry-attempts N` | Number of retry attempts (default: 3) |
| `--batch-size N` | Batch size for processing (default: 50) |
| `--max-results N` | Maximum results to process (default: 10000) |
| `--parallel N` | Max parallel connections (default: 20) |
| `--quick` | Quick scan mode - basic info only |
| `--deep` | Deep scan mode - all enrichment enabled |
| `--focus-vulns` | Focus on vulnerable targets only |
| `--dry-run` | Dry run mode - show what would be done |

### Enrichment Options
| Flag | Description |
|------|-------------|
| `--httpx` | Enrich with page titles and screenshots via httpx |

### Enhanced CVE Options (CVEDB Integration)
| Flag | Description |
|------|-------------|
| `--cve ID` | Fetch specific CVE by ID (e.g., CVE-2021-44228) |
| `--cpe CPE23` | Fetch CVEs by CPE 2.3 string |
| `--product NAME` | Resolve product to CPEs then fetch CVEs |
| `--kev` | Only Known Exploited Vulnerabilities |
| `--epss-top` | Sort by EPSS score descending |
| `--since DATE` | Filter CVEs published on/after YYYY-MM-DD |
| `--until DATE` | Filter CVEs published on/before YYYY-MM-DD |
| `--cve-json` | Output CVEs as JSON |
| `--pretty` | Pretty-print JSON output |
| `--join-cves` | Enrich IP results with inferred CVEs via CPEs |
| `--timeout S` | HTTP timeout for CVEDB requests (seconds) |
| `--min-cvss N` | Minimum CVSS score filter |
| `--max-cvss N` | Maximum CVSS score filter |
| `--min-epss N` | Minimum EPSS score filter |
| `--max-epss N` | Maximum EPSS score filter |
| `--severity LEVEL` | Filter by severity: low, medium, high, critical |
| `--export-csv` | Export results to CSV format |
| `--export-html` | Export results to HTML report |
| `--search TERM` | Search in CVE descriptions |
| `--stats-only` | Show only vulnerability statistics |
| `--cache-time M` | CVE cache time in minutes (default: 60) |

## Examples

### Basic IP Extraction
```bash
# Extract IPs from Shodan search
sqry -q "apache" --limit 10

# Get IPs with domains in CSV format
sqry -q "ssl:true" --domains --with-domains --limit 5

# JSON output with full enrichment
sqry -q "nginx" --json --country US --geo --ports --limit 5
```

### HTTP Probing
```bash
# Use httpx for web reconnaissance
sqry -q "http.title:login" --httpx --limit 20

# Save results with httpx data
sqry -q "port:8080" --httpx --save results.json --json --limit 10
```

### CVE Intelligence
```bash
# Look up specific CVE
sqry --cve CVE-2021-44228 --cve-json --pretty

# Find CVEs for specific CPE
sqry --cpe "cpe:2.3:a:apache:log4j:2.14.1" --limit 5

# Search by product name
sqry --product "apache" --kev --limit 3

# Filter by date range and sort by EPSS
sqry --cpe "cpe:2.3:a:apache:*" --since 2021-01-01 --until 2022-01-01 --epss-top --limit 10

# Enrich IP results with CVEs
sqry -q "apache" --limit 5 --join-cves --json --pretty
```

### Advanced Filtering & Performance
```bash
# Country-specific results with domains
sqry -q "http" --country JP --has-domain --domains --limit 15

# ASN filtering with geolocation
sqry -q "ssh" --asn AS15169 --geo --limit 10

# Shuffle results for randomization
sqry -q "ftp" --shuffle --limit 20

# Quick scan mode for fast results
sqry -q "apache" --quick --limit 50

# Deep scan with rate limiting
sqry -q "nginx" --deep --rate-limit 5 --limit 10

# Focus on vulnerable targets only
sqry -q "apache" --focus-vulns --join-cves --limit 20

# Performance tuning for large scans
sqry -q "http.title:admin" --workers 20 --parallel 50 --batch-size 100 --max-results 5000
```

### Enhanced CVE Analysis
```bash
# Export high-severity CVEs to CSV
sqry --product "apache" --min-cvss 7.0 --export-csv --limit 50

# Generate HTML vulnerability report
sqry --cpe "cpe:2.3:a:apache:*" --export-html --kev

# Search for specific vulnerabilities
sqry --search "remote code execution" --severity critical --stats-only

# Filter by EPSS score and date range
sqry --product "nginx" --min-epss 0.5 --since 2023-01-01 --epss-top

# Get vulnerability statistics for a product
sqry --product "wordpress" --stats-only
```

## Output Formats

### Plain Text
Default output format showing IPs and optional enrichment data in tab-separated format.

### CSV Format
Use `--with-domains` for comma-separated values including IP, domain, and other fields.

### JSON Format
Use `--json` for structured output with all available fields:
```json
{
  "ip": "192.0.2.1",
  "domain": "example.com",
  "org": "Example Corp",
  "asn": "AS64496",
  "country": "US",
  "ports": [80, 443],
  "cpes": ["cpe:2.3:a:apache:http_server:2.4.41"],
  "product": "apache",
  "version": "2.4.41",
  "title": "Example Website",
  "screenshot": "/path/to/screenshot.png",
  "top_cve": {
    "cve_id": "CVE-2021-44228",
    "cvss": 10.0,
    "epss": 0.94470,
    "kev": true
  }
}
```

## Data Sources

- **Shodan**: IP discovery and banner information
- **Shodan InternetDB**: Port and CPE information  
- **ip-api.com**: Geolocation, ASN, and organization data
- **CVEDB**: CVE information, CVSS/EPSS scores, KEV status
- **httpx**: Web page titles and screenshots

## Requirements

- Go 1.19 or later
- Internet connectivity for API calls
- Optional: `httpx` binary for HTTP probing functionality

## Troubleshooting

### Common Issues
- **"httpx binary not found"**: Install httpx from [projectdiscovery/httpx](https://github.com/projectdiscovery/httpx)
- **Timeout errors**: Increase timeout with `--timeout` flag for CVE operations
- **Rate limiting**: Tool includes User-Agent rotation and reasonable delays
- **Empty results**: Verify Shodan query syntax and internet connectivity

### API Limits
- CVEDB: No API key required, but rate limits may apply
- ip-api.com: Free tier allows 1000 requests per month
- Shodan: Web scraping approach, respect rate limits

## Contributing

Contributions are welcome! Please feel free to submit pull requests, report bugs, or suggest new features.

## License

[MIT](LICENSE)

## Author

Made with ❤️ by [@kdairatchi](https://github.com/kdairatchi)
