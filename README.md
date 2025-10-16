# Phishing Domain Crawler

A comprehensive tool for detecting potential phishing domains by analyzing domain permutations, typosquats, and homoglyphs.

## Overview

This tool implements a complete workflow for phishing domain detection:

1. **Canonicalize & Scope**: Normalize target domain and define scope
2. **Passive Subdomain Discovery**: Find subdomains using Amass
3. **Mutation Generation**: Generate domain variations using dnstwist and urlcrazy
4. **Aggregation & Normalization**: Combine and normalize all candidates
5. **DNS Resolution**: Resolve domains using SanicDNS
6. **Enrichment & Validation**: Gather WHOIS, SSL, HTTP info
7. **Scoring & Triage**: Identify high-risk domains
8. **Reporting**: Generate CSV and HTML reports
9. **Evidence Archiving**: Save screenshots, HTML, headers, and certificates

## Requirements

- Python 3.7+
- External tools (optional but recommended):
  - [dnstwist](https://github.com/elceef/dnstwist)
  - [urlcrazy](https://github.com/urbanadventurer/urlcrazy)
  - [SanicDNS](https://github.com/hadriansecurity/sanicdns)
  - [Amass](https://github.com/owasp-amass/amass)

## Installation

1. Clone this repository:
   ```
   git clone https://github.com/yourusername/phishing-domain-crawler.git
   cd phishing-domain-crawler
   ```

2. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

3. (Optional) Install external tools for enhanced functionality:
   - dnstwist: `pip install dnstwist[full]`
   - urlcrazy: Follow instructions at [urlcrazy GitHub](https://github.com/urbanadventurer/urlcrazy)
   - SanicDNS: Follow instructions at [SanicDNS GitHub](https://github.com/hadriansecurity/sanicdns)
   - Amass: Follow instructions at [Amass GitHub](https://github.com/owasp-amass/amass)

## Usage

Basic usage:

```
python phishing_crawler.py example.com
```

Advanced usage:

```
python phishing_crawler.py example.com -o output_directory -t 20
```

### Parameters

- `domain`: Target domain to analyze
- `-o, --output`: Output directory (default: "output")
- `-t, --threads`: Maximum number of threads (default: 10)

## Output

The tool generates the following outputs in the specified directory:

- `subdomains.txt`: Discovered subdomains
- `mutations.txt`: Generated domain mutations
- `normalized_domains.txt`: Aggregated and normalized domains
- `resolved_domains.txt`: Domains that resolved to an IP address
- `enriched_domains.json`: Detailed information about resolved domains
- `scored_domains.json`: Domains with risk scores and factors
- `phishing_report.csv`: CSV report of potential phishing domains
- `phishing_report.html`: HTML report of potential phishing domains
- `evidence/`: Directory containing evidence for high-risk domains

## Workflow Details

### 1. Canonicalize & Scope

- Normalize the target domain (lowercase, remove www)
- Define related TLDs to check

### 2. Passive Subdomain Discovery

- Use Amass to discover subdomains through passive techniques
- Save discovered subdomains to a file

### 3. Mutation Generation

- Generate domain mutations using various algorithms:
  - Character omission
  - Character replacement
  - Character insertion
  - Homoglyphs
  - Bitsquatting

### 4. Aggregation & Normalization

- Combine subdomains and mutations
- Normalize domains (lowercase, punycode)
- Remove duplicates

### 5. DNS Resolution

- Resolve DNS for candidate domains
- Keep only domains that resolve to an IP address

### 6. Enrichment & Validation

- Gather WHOIS information (registrar, creation date, etc.)
- Check SSL certificates
- Fetch HTTP information (status, redirects, login forms)
- Calculate similarity to target domain

### 7. Scoring & Triage

- Score domains based on risk factors:
  - Domain similarity
  - Domain age
  - SSL certificate
  - Login form presence
  - Redirects
- Assign risk levels (Critical, High, Medium, Low)

### 8. Reporting

- Generate CSV report
- Generate HTML report with summary and details

### 9. Evidence Archiving

- Save domain information
- Create placeholders for screenshots, HTML content, HTTP headers, and SSL certificates

## License

MIT

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.