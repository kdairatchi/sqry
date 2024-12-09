<h1 align="center">sqry</h1>

> sqry is Shodan Query

`sqry extracts IPs from Shodan searches. just the IPs you need.`
# Sqry

Sqry is a lightweight command-line tool written in Go that allows users to query Shodan for IP addresses based on a specific search query. It extracts IPv4 addresses from the Shodan results, filters out private or reserved IPs, removes duplicates, and outputs the clean list of public IPs.

- Extract IPs from Shodan
- Random User-Agent rotation
- Clean, pipe-friendly output
- Zero dependencies (just bash & curl)

- Fetches data directly from Shodan's search facet endpoint.
- Uses a random User-Agent for each request to avoid detection.
- Extracts and validates IPv4 addresses using regex.
- Filters out private, reserved, and non-routable IP ranges.
- Ensures unique IP addresses in the output.
- A valid Shodan API query string (no API key required for this tool, as it scrapes public search result)

<br>
<br>

`installation`
> 
```bash
go install github.com/Karthik-HR0/sqry@latest
```

<br>
<br>

`arguments`
<pre>
  -q   : Search query (required)
</pre>

<br>
<br>

`example commands`
```bash
sqry -q "apache" > apache_ips.txt # Search for apache servers
```
```bash
sqry -q 'org:\"Google LLC\"' # Search with organization filter
```
```bash
sqry -q "port:443" | sort -u # Search with port filter
```
```bash
sqry -q "apache" | xargs -I {} nmap -sV {} # Scan found IPs with nmap
```
```bash
sqry -q "apache" | tee ips.txt | wc -l # Save to file and count results
```
```bash
sqry -q "apache" | grep -v "^10\." > public_ips.txt # Filter and process results
```

<br>
<br>

`If you see no results`
- Check your query syntax
- Ensure you have curl installed
- Check your internet connection


<br>
<br>
<br>
<p align="center">
Made with <3 by <a href="https://github.com/KARTHIK-HR0" >@Karthik-HR0</a>
<br>
</p>
