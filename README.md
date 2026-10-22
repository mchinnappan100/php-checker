# php-vuln-check.js — Node.js CLI (zero dependencies)

```bash
# check local PHP binary
node php-vuln-check.js

# check a single site via HTTP response headers
node php-vuln-check.js --url https://example.com

# bulk-check a list of URLs (one per line)
node php-vuln-check.js --file hosts.txt

# JSON output — pipe into monitoring or alerting
node php-vuln-check.js --file hosts.txt --json

# exit code 1 if any host is vulnerable or EOL
# exit code 0 if all hosts are patched
```

The checker reads the X-Powered-By and Server HTTP response headers to detect exposed PHP versions. Servers that suppress those headers are reported as HEADER_HIDDEN — which is good practice but requires a direct local check. Source: php-vuln-check.js in this repo.
