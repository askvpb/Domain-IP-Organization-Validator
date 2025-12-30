# Domain/IP Organization Validator

A powerful Python script for validating domain and IP ownership, performing WHOIS lookups, and checking organizational affiliations at scale.

## Features

- 🔍 **Bulk Domain/IP Validation**: Process hundreds of domains/IPs from CSV files
- 🏢 **Organization Verification**: Check if domains/IPs belong to specific organizations
- 📊 **Comprehensive WHOIS Data**: Extract registrant, registrar, dates, emails, and more
- 🌐 **DNS Resolution**: Resolve domains to IP addresses with custom DNS server support
- ⚡ **Parallel Processing**: Multi-threaded execution for faster processing
- 🛡️ **Robust Error Handling**: Timeout management, retry logic, and rate limiting
- 📁 **Flexible Output**: Console summary and CSV export options
- 🌏 **Special Handling**: Optimized for problematic TLDs (.com.au, .co.uk, etc.)

## Table of Contents

- [Installation](#installation)
- [Quick Start](#quick-start)
- [Usage Examples](#usage-examples)
- [Input Format](#input-format)
- [Output Format](#output-format)
- [Command Line Options](#command-line-options)
- [Handling Timeouts](#handling-timeouts)
- [Advanced Features](#advanced-features)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [License](#license)

## Installation

### Prerequisites

- Python 3.7 or higher
- pip (Python package manager)

### Required Libraries

```bash
pip install python-whois dnspython requests urllib3
```

### Clone or Download

```bash
# Clone the repository
git clone https://github.com/yourusername/domain-validator.git
cd domain-validator

# Or download the script directly
wget https://raw.githubusercontent.com/yourusername/domain-validator/main/domain-validator.py
```

## Quick Start

### Basic Registrant Lookup

```bash
# Look up registrant information for all domains in the CSV
python domain-validator.py domains.csv

# Save results to a CSV file
python domain-validator.py domains.csv -out results.csv
```

### Organization Validation

```bash
# Check if domains belong to Microsoft
python domain-validator.py domains.csv -o "Microsoft Corporation"

# Check with organization variations
python domain-validator.py domains.csv -o "Google" -v "Google LLC" "Alphabet Inc"
```

## Usage Examples

### 1. Basic Operations

```bash
# Simple registrant lookup
python domain-validator.py input.csv

# With output file
python domain-validator.py input.csv -out results.csv

# Organization check
python domain-validator.py input.csv -o "Amazon"
```

### 2. Performance Optimization

```bash
# Use 10 parallel workers for faster processing
python domain-validator.py large_list.csv -w 10

# Sequential processing (more reliable for problematic domains)
python domain-validator.py domains.csv --no-batch

# Increase timeout for slow WHOIS servers
python domain-validator.py domains.csv -t 30
```

### 3. Handling Problematic Domains

```bash
# Skip DNS resolution (faster)
python domain-validator.py domains.csv --skip-dns

# DNS-only mode (no WHOIS lookups)
python domain-validator.py domains.csv --dns-only

# Extract base domains from subdomains
python domain-validator.py domains.csv --base-domains-only

# Combine optimizations for .com.au domains
python domain-validator.py au_domains.csv --base-domains-only --skip-dns -w 1
```

### 4. Custom DNS Servers

```bash
# Use Google's DNS
python domain-validator.py domains.csv --dns-servers 8.8.8.8 8.8.4.4

# Use Cloudflare's DNS
python domain-validator.py domains.csv --dns-servers 1.1.1.1 1.0.0.1

# Multiple DNS servers for redundancy
python domain-validator.py domains.csv --dns-servers 8.8.8.8 1.1.1.1 208.67.222.222
```

## Input Format

### CSV Structure

The script accepts CSV files with domains and/or IP addresses. Headers are automatically detected and skipped.

**Example 1: Simple list**
```csv
domain_or_ip
google.com
microsoft.com
8.8.8.8
192.168.1.1
```

**Example 2: Multiple per row**
```csv
domains
google.com,youtube.com,gmail.com
microsoft.com,azure.com,github.com
```

**Example 3: Mixed format**
```csv
google.com
8.8.8.8,8.8.4.4
microsoft.com,azure.com
subdomain.example.com
```

### Supported Input Types

- ✅ Domain names: `example.com`, `subdomain.example.com`
- ✅ IP addresses: `192.168.1.1`, `2001:0db8:85a3:0000:0000:8a2e:0370:7334`
- ✅ Subdomains: Automatically handled with `--base-domains-only` flag
- ✅ International domains: Support for IDN domains

## Output Format

### Console Output

The script provides a detailed summary including:
- Processing statistics
- Organization matches (if applicable)
- Error reports
- Timing information

**Example output:**
```
============================================================
PROCESSING STATISTICS
============================================================
Total entries: 100
Valid format: 98
Errors: 2
Timeouts: 5
Successful lookups: 93

Registrant Information:
With organization info: 89/100
With registrant info: 85/100
============================================================

SAMPLE RESULTS (first 5):

📍 google.com (DOMAIN)
   Organization: Google LLC
   Registrant: Domain Administrator
   Registrar: MarkMonitor Inc.
   Created: 1997-09-15
   Expires: 2028-09-14
```

### CSV Output

When using the `-out` flag, results are saved with the following columns:

**For registrant lookup mode:**
- `input` - Original domain/IP
- `type` - domain or ip
- `valid_format` - true/false
- `registrant` - Registrant name
- `whois_org` - Organization from WHOIS
- `emails` - Contact emails
- `registrar` - Domain registrar
- `creation_date` - Registration date
- `expiration_date` - Expiry date
- `name_servers` - DNS servers
- `status` - Domain status flags
- `error` - Error message if any

**For organization validation mode:**
- All above fields plus:
- `belongs_to_org` - true/false
- `confidence` - Match confidence (0.0-1.0)
- `matched_string` - The string that matched

## Command Line Options

### Required Arguments

| Argument | Description |
|----------|-------------|
| `csv_file` | Path to input CSV file containing domains/IPs |

### Optional Arguments

| Option | Description | Default |
|--------|-------------|---------|
| `-o, --organization` | Target organization name to validate against | None |
| `-v, --variations` | Organization name variations/subsidiaries | None |
| `-out, --output` | Output CSV file path for results | None |
| `-t, --timeout` | WHOIS lookup timeout in seconds | 10 |
| `-w, --workers` | Number of parallel workers | 3 |
| `--no-batch` | Disable batch processing (sequential mode) | False |
| `--skip-dns` | Skip DNS resolution for faster processing | False |
| `--skip-whois` | Skip WHOIS lookups entirely | False |
| `--dns-only` | Only perform DNS lookups, skip WHOIS | False |
| `--base-domains-only` | Extract and lookup base domains only | False |
| `--dns-servers` | Custom DNS servers to use | System default |
| `--whois-server` | Custom WHOIS server | Auto-detect |

## Handling Timeouts

### Common Timeout Issues

Timeouts often occur with:
- Australian domains (.com.au)
- Large subdomain lists
- Rate-limited WHOIS servers
- Corporate firewalls

### Solutions

#### For .com.au domains:
```bash
# Option 1: DNS only (fastest)
python domain-validator.py au_domains.csv --dns-only

# Option 2: Base domains with single worker
python domain-validator.py au_domains.csv --base-domains-only -w 1

# Option 3: Skip WHOIS entirely
python domain-validator.py au_domains.csv --skip-whois
```

#### For large lists:
```bash
# Increase timeout and reduce workers
python domain-validator.py large_list.csv -t 30 -w 2

# Skip DNS to focus on WHOIS
python domain-validator.py large_list.csv --skip-dns
```

#### For corporate networks:
```bash
# Use public DNS servers
python domain-validator.py domains.csv --dns-servers 8.8.8.8 1.1.1.1

# Sequential processing
python domain-validator.py domains.csv --no-batch -w 1
```

## Advanced Features

### Rate Limiting

The script includes automatic rate limiting to avoid being blocked:
- Default: 2 requests per second
- Adjustable for different WHOIS servers
- Exponential backoff on failures

### Caching

Results are cached during execution to:
- Avoid duplicate lookups
- Speed up processing
- Reduce server load

### Subdomain Handling

The `--base-domains-only` flag intelligently extracts base domains:
- `admin.example.com` → `example.com`
- `sub.domain.co.uk` → `domain.co.uk`
- `deep.subdomain.example.com.au` → `example.com.au`

### Multi-threading

Parallel processing with configurable workers:
- Default: 3 workers
- Maximum recommended: 10 workers
- Use 1 worker for problematic domains

## Troubleshooting

### Issue: "closing socket - timed out"

**Solution:**
```bash
# Use DNS-only mode
python domain-validator.py domains.csv --dns-only

# Or increase timeout with single worker
python domain-validator.py domains.csv -t 30 -w 1 --no-batch
```

### Issue: "No match found" for subdomains

**Solution:**
```bash
# Extract base domains
python domain-validator.py domains.csv --base-domains-only
```

### Issue: Slow processing

**Solution:**
```bash
# Increase workers and skip DNS
python domain-validator.py domains.csv -w 10 --skip-dns
```

### Issue: Rate limiting errors

**Solution:**
```bash
# Reduce workers and add delays
python domain-validator.py domains.csv -w 1 --no-batch
```

## Performance Tips

1. **For large lists (1000+ domains):**
   - Use `--skip-dns` if IP resolution not needed
   - Increase workers: `-w 10`
   - Use batch mode (default)

2. **For accuracy:**
   - Use `--base-domains-only` for subdomain lists
   - Include organization variations with `-v`
   - Don't skip WHOIS unless necessary

3. **For speed:**
   - Use `--dns-only` for quick availability checks
   - Use public DNS servers
   - Enable parallel processing

## Output Examples

### Successful Lookup
```
✓ google.com - Google LLC (confidence: 90%)
  Registrar: MarkMonitor Inc.
  Created: 1997-09-15
  Expires: 2028-09-14
```

### Failed Lookup
```
✗ invalid-domain-xyz - Timeout after retries
  Error: Socket timeout
```

### Organization Match
```
✓ github.com - Belongs to Microsoft Corporation
  Matched: "Microsoft Corporation" in registrant
  Confidence: 90%
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

### Development Setup

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

### Areas for Contribution

- Additional WHOIS server support
- Improved parsing for specific TLDs
- Performance optimizations
- Additional output formats (JSON, XML)
- GUI interface
- Docker containerization

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Built with [python-whois](https://pypi.org/project/python-whois/)
- DNS resolution via [dnspython](https://www.dnspython.org/)
- Inspired by the need for bulk domain validation in cybersecurity operations

## Author

Created for cybersecurity professionals and system administrators who need to validate domain ownership at scale.

## Support

For issues, questions, or suggestions:
1. Check the [Troubleshooting](#troubleshooting) section
2. Open an issue on GitHub
3. Consult the examples in this README

---

**Note:** This tool is for legitimate security research and administrative purposes only. Please respect rate limits and terms of service of WHOIS providers.