# sqry

sqry is a lightweight command-line tool written in Go that queries Shodan and extracts IPv4 addresses. It filters out private and reserved ranges, removes duplicates, and can optionally enrich results with domains, ports, geolocation, and CVE data.

## Features
- Extract IPs from Shodan searches
- Filter out private and reserved ranges
- Random User-Agent rotation
- Optional enrichment with domains, ports, ASN, country, and CVE information
- HTTP probing via [httpx](https://github.com/projectdiscovery/httpx) for titles and screenshots
- Output in plain text, CSV, or JSON

## Installation
```bash
go install github.com/Karthik-HR0/sqry@latest
```

## Usage
```bash
sqry -q <query> [options]
```
Run `sqry -h` to view all available flags.

## Examples
```bash
sqry -q "apache" --limit 10
sqry -q "ssl:true" --domains --with-domains
sqry -q "nginx" --json --country US --limit 5
sqry -q "http" --httpx --limit 20
sqry --cve CVE-2016-10087 --cve-json --pretty
```

## Troubleshooting
- Ensure your Shodan query syntax is valid
- Confirm internet connectivity
- The `httpx` option requires the `httpx` binary in your `PATH`

## License
[MIT](LICENSE)

Made with ❤️ by [@Karthik-HR0](https://github.com/KARTHIK-HR0)
