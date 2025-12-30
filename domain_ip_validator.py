#!/usr/bin/env python3
"""
Domain/IP Organization Validator Script
Validates whether domains or IPs belong to specific organizations
Optimized for large-scale lookups with timeout handling

USAGE EXAMPLES:
==============

1. BASIC REGISTRANT LOOKUP (no organization check):
   python domain-validator.py domains.csv
   python domain-validator.py domains.csv -out results.csv

2. ORGANIZATION VALIDATION:
   python domain-validator.py domains.csv -o "Microsoft Corporation"
   python domain-validator.py domains.csv -o "Google" -v "Google LLC" "Alphabet Inc"

3. HANDLING TIMEOUTS (for problematic domains like .com.au):
   python domain-validator.py domains.csv --skip-whois --dns-only
   python domain-validator.py domains.csv --base-domains-only --skip-dns
   python domain-validator.py domains.csv -t 30 -w 1 --no-batch

4. CUSTOM SETTINGS:
   python domain-validator.py domains.csv --dns-servers 8.8.8.8 1.1.1.1
   python domain-validator.py domains.csv -w 10 -t 20
   python domain-validator.py domains.csv --whois-server whois.apnic.net

INPUT CSV FORMAT:
================
domains.csv can contain:
- One domain/IP per line
- Multiple domains/IPs per line (comma-separated)
- Headers are automatically detected and skipped

Example CSV content:
--------------------
domain_or_ip
google.com
8.8.8.8
microsoft.com,azure.com,github.com
192.168.1.1

OUTPUT:
=======
The script provides:
- Registrant/organization information
- WHOIS details (registrar, dates, emails)
- DNS resolution results
- Organization matching with confidence scores
- Summary statistics
- Optional CSV export with -out flag
"""

import csv
import socket
import ipaddress
import argparse
import sys
import time
import threading
from typing import Dict, List, Tuple, Optional
import subprocess
import json
import re
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from queue import Queue
import signal

try:
    import whois
    import dns.resolver
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
except ImportError as e:
    print(f"Missing required module: {e}")
    print("Please install requirements: pip install python-whois dnspython requests urllib3")
    sys.exit(1)

# Global settings for timeouts and retries
SOCKET_TIMEOUT = 3  # seconds (reduced)
WHOIS_TIMEOUT = 10  # seconds
DNS_TIMEOUT = 2  # seconds (reduced)
HTTP_TIMEOUT = 5  # seconds
MAX_RETRIES = 1  # Reduced retries for faster processing
BATCH_SIZE = 10  # Process in batches to avoid overwhelming
MAX_WORKERS = 3  # Reduced default workers to avoid overwhelming servers

# Australian WHOIS server that might work better
AU_WHOIS_SERVERS = [
    'whois.auda.org.au',
    'whois.aunic.net',
    'whois.apnic.net'
]

class RateLimiter:
    """Simple rate limiter to avoid overwhelming servers"""
    def __init__(self, max_per_second=2):
        self.max_per_second = max_per_second
        self.min_interval = 1.0 / max_per_second
        self.last_call = 0
        self.lock = threading.Lock()
    
    def wait(self):
        with self.lock:
            now = time.time()
            time_since_last = now - self.last_call
            if time_since_last < self.min_interval:
                time.sleep(self.min_interval - time_since_last)
            self.last_call = time.time()

class OrganizationValidator:
    def __init__(self, target_org: str = None, org_variations: List[str] = None, 
                 timeout: int = WHOIS_TIMEOUT, max_workers: int = MAX_WORKERS,
                 dns_servers: List[str] = None, skip_whois: bool = False,
                 dns_only: bool = False, whois_server: str = None):
        """
        Initialize validator with target organization details
        
        Args:
            target_org: Primary organization name to match
            org_variations: List of organization name variations/subsidiaries
            timeout: Timeout for network operations in seconds
            max_workers: Number of parallel workers for batch processing
            dns_servers: Custom DNS servers to use (e.g., ['8.8.8.8', '1.1.1.1'])
            skip_whois: Skip WHOIS lookups entirely
            dns_only: Only perform DNS lookups
            whois_server: Custom WHOIS server to use
        """
        self.target_org = target_org.lower() if target_org else None
        self.org_variations = [v.lower() for v in (org_variations or [])]
        if self.target_org:
            self.org_variations.append(self.target_org)
        
        # Cache for resolved IPs and WHOIS data
        self.cache = {}
        
        # Timeout settings
        self.timeout = timeout
        self.max_workers = max_workers
        self.skip_whois = skip_whois
        self.dns_only = dns_only
        self.whois_server = whois_server
        
        # Rate limiter to avoid overwhelming WHOIS servers
        self.rate_limiter = RateLimiter(max_per_second=1)  # Slower rate for .au domains
        
        # Configure DNS resolver with timeout
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = DNS_TIMEOUT
        self.resolver.lifetime = DNS_TIMEOUT
        
        # Use custom DNS servers if provided
        if dns_servers:
            self.resolver.nameservers = dns_servers
            print(f"Using custom DNS servers: {', '.join(dns_servers)}")
        else:
            # Use system default DNS servers
            try:
                print(f"Using system DNS servers: {', '.join(self.resolver.nameservers[:3])}")
            except:
                print("Using system DNS servers")
        
        if skip_whois:
            print("WHOIS lookups disabled (--skip-whois flag)")
        elif dns_only:
            print("DNS-only mode (--dns-only flag)")
        
        # Configure socket timeout
        socket.setdefaulttimeout(SOCKET_TIMEOUT)
        
        # Setup HTTP session with retry strategy
        self.session = self._create_http_session()
        
        # Statistics
        self.stats = {
            'processed': 0,
            'timeouts': 0,
            'errors': 0,
            'successful': 0
        }
    
    def _create_http_session(self):
        """Create HTTP session with retry strategy"""
        session = requests.Session()
        retry_strategy = Retry(
            total=MAX_RETRIES,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        return session
    
    def is_valid_domain(self, domain: str) -> bool:
        """Check if string is a valid domain name"""
        if not domain:
            return False
        domain_pattern = re.compile(
            r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$'
        )
        return bool(domain_pattern.match(domain))
    
    def is_valid_ip(self, ip: str) -> bool:
        """Check if string is a valid IP address"""
        if not ip:
            return False
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False
    
    def resolve_domain_to_ip(self, domain: str) -> List[str]:
        """Resolve domain to IP addresses with timeout handling"""
        if domain in self.cache:
            return self.cache[domain].get('ips', [])
        
        ips = []
        try:
            # Try A records with timeout
            try:
                answers = self.resolver.resolve(domain, 'A')
                ips.extend([str(rdata) for rdata in answers])
            except dns.resolver.NXDOMAIN:
                pass
            except dns.resolver.Timeout:
                self.stats['timeouts'] += 1
                print(f"  ⚠ DNS timeout for {domain}")
            except Exception:
                pass
            
            # Try AAAA records (IPv6) if no A records found
            if not ips:
                try:
                    answers = self.resolver.resolve(domain, 'AAAA')
                    ips.extend([str(rdata) for rdata in answers])
                except:
                    pass
            
            # Fallback to socket resolution with timeout
            if not ips:
                try:
                    # Create a socket with custom timeout
                    old_timeout = socket.getdefaulttimeout()
                    socket.setdefaulttimeout(DNS_TIMEOUT)
                    result = socket.getaddrinfo(domain, None)
                    ips = list(set([r[4][0] for r in result]))
                    socket.setdefaulttimeout(old_timeout)
                except socket.timeout:
                    self.stats['timeouts'] += 1
                    print(f"  ⚠ Socket timeout for {domain}")
                except:
                    pass
        except Exception as e:
            print(f"  ⚠ Error resolving {domain}: {str(e)[:50]}")
        
        self.cache[domain] = {'ips': ips}
        return ips
    
    def get_whois_info_with_retry(self, target: str, retries: int = MAX_RETRIES) -> Dict:
        """Get WHOIS information with retry logic and timeout handling"""
        cache_key = f"whois_{target}"
        if cache_key in self.cache:
            return self.cache[cache_key]
        
        # Apply rate limiting
        self.rate_limiter.wait()
        
        # Check if it's a subdomain and try to get the base domain
        base_domain = target
        if '.' in target:
            parts = target.split('.')
            # For subdomains, try the base domain (e.g., amp.com.au from subdomain.amp.com.au)
            if len(parts) > 2:
                # Handle .com.au, .co.uk, etc.
                if len(parts) > 3 and parts[-2] in ['com', 'co', 'net', 'org', 'gov', 'edu']:
                    base_domain = '.'.join(parts[-3:])
                else:
                    base_domain = '.'.join(parts[-2:])
        
        # Try alternative WHOIS methods based on TLD
        tld = target.split('.')[-1] if '.' in target else ''
        
        # Default result structure
        result = {
            'org': None,
            'emails': [],
            'registrant': None,
            'registrar': None,
            'creation_date': None,
            'expiration_date': None,
            'name_servers': [],
            'status': [],
            'raw': '',
            'error': None
        }
        
        # Try python-whois first
        for attempt in range(retries + 1):
            try:
                # Use threading timeout for more reliable timeout handling
                import threading
                whois_result = [None]
                whois_error = [None]
                
                def whois_lookup():
                    try:
                        # Try with base domain if subdomain
                        lookup_target = base_domain if base_domain != target else target
                        whois_result[0] = whois.whois(lookup_target, timeout=self.timeout)
                    except Exception as e:
                        whois_error[0] = e
                
                thread = threading.Thread(target=whois_lookup)
                thread.daemon = True
                thread.start()
                thread.join(timeout=self.timeout)
                
                if thread.is_alive():
                    # Thread is still running, it's a timeout
                    self.stats['timeouts'] += 1
                    if attempt < retries:
                        print(f"  ⚠ WHOIS timeout for {target}, retrying ({attempt + 1}/{retries})...")
                        time.sleep(1 + attempt)  # Shorter backoff
                        continue
                    else:
                        result['error'] = 'Timeout after retries'
                        # Try fallback method for .com.au domains
                        if tld == 'au' or target.endswith('.com.au'):
                            result = self._whois_fallback_aunic(base_domain, result)
                        break
                
                if whois_error[0]:
                    raise whois_error[0]
                
                w = whois_result[0]
                if w:
                    # Extract information safely
                    result['org'] = getattr(w, 'org', None) or getattr(w, 'organization', None)
                    result['registrant'] = getattr(w, 'registrant', None) or getattr(w, 'registrant_name', None)
                    result['registrar'] = getattr(w, 'registrar', None)
                    
                    # Handle emails
                    emails = getattr(w, 'emails', [])
                    if isinstance(emails, str):
                        result['emails'] = [emails]
                    elif isinstance(emails, list):
                        result['emails'] = emails
                    
                    # Handle dates
                    for date_field in ['creation_date', 'expiration_date']:
                        date_val = getattr(w, date_field, None)
                        if date_val:
                            if isinstance(date_val, list):
                                date_val = date_val[0]
                            if hasattr(date_val, 'strftime'):
                                result[date_field] = date_val.strftime('%Y-%m-%d')
                            else:
                                result[date_field] = str(date_val)
                    
                    # Handle name servers
                    ns = getattr(w, 'name_servers', [])
                    if isinstance(ns, str):
                        result['name_servers'] = [ns]
                    elif isinstance(ns, list):
                        result['name_servers'] = [n.lower() if isinstance(n, str) else str(n) for n in ns]
                    
                    # Handle status
                    status = getattr(w, 'status', [])
                    if isinstance(status, str):
                        result['status'] = [status]
                    elif isinstance(status, list):
                        result['status'] = status
                    
                    result['raw'] = str(w)
                    self.stats['successful'] += 1
                    
                self.cache[cache_key] = result
                return result
                    
            except Exception as e:
                error_msg = str(e)
                if 'closing socket - timed out' in error_msg or 'timed out' in error_msg.lower():
                    self.stats['timeouts'] += 1
                    if attempt < retries:
                        print(f"  ⚠ Socket timeout for {target}, retrying ({attempt + 1}/{retries})...")
                        time.sleep(1 + attempt)
                    else:
                        result['error'] = 'Socket timeout'
                        # Try fallback for problematic TLDs
                        if tld == 'au' or target.endswith('.com.au'):
                            result = self._whois_fallback_aunic(base_domain, result)
                else:
                    if attempt < retries and 'No match' not in error_msg:
                        print(f"  ⚠ Error for {target}: {error_msg[:50]}, retrying...")
                        time.sleep(1 + attempt)
                    else:
                        self.stats['errors'] += 1
                        result['error'] = error_msg[:100]
                        break
        
        self.cache[cache_key] = result
        return result
    
    def _whois_fallback_aunic(self, domain: str, result: Dict) -> Dict:
        """Fallback WHOIS for .au domains using direct query"""
        try:
            import subprocess
            # Try using system whois command if available
            output = subprocess.run(
                ['whois', '-h', 'whois.auda.org.au', domain],
                capture_output=True,
                text=True,
                timeout=5
            )
            if output.stdout:
                lines = output.stdout.split('\n')
                for line in lines:
                    if 'Registrant:' in line:
                        result['registrant'] = line.split(':', 1)[1].strip()
                    elif 'Registrant Name:' in line:
                        result['registrant'] = line.split(':', 1)[1].strip()
                    elif 'Registrar Name:' in line:
                        result['registrar'] = line.split(':', 1)[1].strip()
                result['raw'] = output.stdout
                print(f"  ℹ Used fallback WHOIS for {domain}")
        except:
            pass
        return result
    
    def _timeout_handler(self, signum, frame):
        """Handler for timeout signal"""
        raise TimeoutError("Operation timed out")
    
    def check_rdap(self, target: str) -> Dict:
        """Check RDAP with timeout handling"""
        try:
            if self.is_valid_ip(target):
                url = f"https://rdap.arin.net/registry/ip/{target}"
            else:
                url = f"https://rdap.verisign.com/domain/{target}"
            
            response = self.session.get(url, timeout=HTTP_TIMEOUT)
            if response.status_code == 200:
                data = response.json()
                return {
                    'org': data.get('name', ''),
                    'handle': data.get('handle', ''),
                    'entities': data.get('entities', [])
                }
        except (requests.Timeout, requests.ConnectionError):
            self.stats['timeouts'] += 1
        except Exception:
            pass
        return {}
    
    def check_organization_match(self, whois_data: Dict, rdap_data: Dict = None) -> Tuple[bool, str, float]:
        """Check if WHOIS/RDAP data matches target organization"""
        if not self.target_org:
            return False, '', 0.0
            
        search_texts = []
        
        if whois_data.get('org'):
            search_texts.append(str(whois_data['org']).lower())
        if whois_data.get('registrant'):
            search_texts.append(str(whois_data['registrant']).lower())
        if whois_data.get('emails'):
            search_texts.extend([e.lower() for e in whois_data['emails']])
        if whois_data.get('raw'):
            search_texts.append(whois_data['raw'].lower())
        
        if rdap_data:
            if rdap_data.get('org'):
                search_texts.append(str(rdap_data['org']).lower())
        
        for text in search_texts:
            for org_variant in self.org_variations:
                if org_variant in text:
                    if text in [whois_data.get('org', '').lower(), 
                               whois_data.get('registrant', '').lower()]:
                        confidence = 0.9
                    elif any(org_variant in email for email in whois_data.get('emails', [])):
                        confidence = 0.8
                    else:
                        confidence = 0.6
                    
                    return True, org_variant, confidence
        
        return False, '', 0.0
    
    def validate_entry(self, entry: str) -> Dict:
        """Validate a single domain or IP with timeout handling"""
        entry = entry.strip()
        self.stats['processed'] += 1
        
        # Extract base domain if requested
        original_entry = entry
        if hasattr(OrganizationValidator, 'base_domains_only') and OrganizationValidator.base_domains_only:
            if '.' in entry and self.is_valid_domain(entry):
                parts = entry.split('.')
                if len(parts) > 2:
                    # Handle .com.au, .co.uk, etc.
                    if len(parts) > 3 and parts[-2] in ['com', 'co', 'net', 'org', 'gov', 'edu']:
                        entry = '.'.join(parts[-3:])
                    else:
                        entry = '.'.join(parts[-2:])
        
        result = {
            'input': original_entry,
            'processed_as': entry if entry != original_entry else '',
            'type': 'unknown',
            'valid_format': False,
            'resolved_ips': [],
            'belongs_to_org': False,
            'matched_string': '',
            'confidence': 0.0,
            'whois_org': '',
            'registrant': '',
            'registrar': '',
            'emails': [],
            'creation_date': '',
            'expiration_date': '',
            'name_servers': [],
            'status': [],
            'error': None
        }
        
        # Determine type and validity
        if self.is_valid_ip(entry):
            result['type'] = 'ip'
            result['valid_format'] = True
        elif self.is_valid_domain(entry):
            result['type'] = 'domain'
            result['valid_format'] = True
            # Skip DNS resolution if flag is set or in DNS-only mode
            if not (hasattr(OrganizationValidator, 'skip_dns') and OrganizationValidator.skip_dns):
                result['resolved_ips'] = self.resolve_domain_to_ip(entry)
        else:
            result['error'] = 'Invalid format'
            return result
        
        # Skip WHOIS if requested
        if self.skip_whois or self.dns_only:
            if self.dns_only and result['resolved_ips']:
                result['whois_org'] = f"DNS resolved to {len(result['resolved_ips'])} IP(s)"
            return result
        
        # Get WHOIS information with retry
        whois_data = self.get_whois_info_with_retry(entry)
        
        if whois_data.get('org'):
            result['whois_org'] = whois_data['org']
        if whois_data.get('registrant'):
            result['registrant'] = whois_data['registrant']
        if whois_data.get('registrar'):
            result['registrar'] = whois_data['registrar']
        if whois_data.get('emails'):
            result['emails'] = whois_data['emails']
        if whois_data.get('creation_date'):
            result['creation_date'] = whois_data['creation_date']
        if whois_data.get('expiration_date'):
            result['expiration_date'] = whois_data['expiration_date']
        if whois_data.get('name_servers'):
            result['name_servers'] = whois_data['name_servers']
        if whois_data.get('status'):
            result['status'] = whois_data['status']
        
        # Get RDAP information if needed
        if self.target_org and not (hasattr(OrganizationValidator, 'skip_dns') and OrganizationValidator.skip_dns):
            rdap_data = self.check_rdap(entry)
            matches, matched_string, confidence = self.check_organization_match(whois_data, rdap_data)
            result['belongs_to_org'] = matches
            result['matched_string'] = matched_string
            result['confidence'] = confidence
        
        if whois_data.get('error'):
            result['error'] = whois_data['error']
        
        return result
    
    def process_batch(self, entries: List[str]) -> List[Dict]:
        """Process a batch of entries with parallel execution"""
        results = []
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {executor.submit(self.validate_entry, entry): entry 
                      for entry in entries}
            
            for future in as_completed(futures):
                entry = futures[future]
                try:
                    result = future.result(timeout=self.timeout * 2)
                    results.append(result)
                    
                    # Print progress
                    status = "✓" if not result.get('error') else "✗"
                    print(f"{status} Processed: {entry} [{self.stats['processed']}/{len(entries)}]")
                    
                except Exception as e:
                    print(f"✗ Failed to process {entry}: {str(e)[:50]}")
                    results.append({
                        'input': entry,
                        'error': f"Processing failed: {str(e)[:50]}",
                        'type': 'unknown',
                        'valid_format': False
                    })
        
        return results
    
    def process_csv(self, csv_file: str, output_file: str = None, batch_mode: bool = True) -> List[Dict]:
        """Process CSV file with batch processing and timeout handling"""
        all_entries = []
        results = []
        
        # Read all entries first
        with open(csv_file, 'r', newline='', encoding='utf-8') as f:
            reader = csv.reader(f)
            
            first_row = next(reader, None)
            if first_row and not (self.is_valid_domain(first_row[0]) or self.is_valid_ip(first_row[0])):
                print(f"Skipping header: {first_row}")
            else:
                if first_row:
                    all_entries.extend([e.strip() for e in first_row if e.strip()])
            
            for row in reader:
                all_entries.extend([e.strip() for e in row if e.strip()])
        
        print(f"Found {len(all_entries)} entries to process")
        print(f"Using {'batch' if batch_mode else 'sequential'} processing with {self.max_workers} workers")
        print("-" * 60)
        
        # Process entries
        if batch_mode and len(all_entries) > 5:
            # Process in batches for better performance
            for i in range(0, len(all_entries), BATCH_SIZE):
                batch = all_entries[i:i + BATCH_SIZE]
                print(f"\nProcessing batch {i // BATCH_SIZE + 1} ({len(batch)} entries)")
                batch_results = self.process_batch(batch)
                results.extend(batch_results)
                
                # Small delay between batches
                if i + BATCH_SIZE < len(all_entries):
                    time.sleep(1)
        else:
            # Sequential processing for small lists
            for entry in all_entries:
                print(f"Processing: {entry}")
                results.append(self.validate_entry(entry))
        
        # Write output CSV if specified
        if output_file:
            self.write_results_csv(results, output_file)
        
        return results
    
    def write_results_csv(self, results: List[Dict], output_file: str):
        """Write validation results to CSV file"""
        with open(output_file, 'w', newline='', encoding='utf-8') as f:
            if self.target_org:
                # Organization validation mode
                fieldnames = ['input', 'type', 'valid_format', 'belongs_to_org', 
                            'confidence', 'matched_string', 'whois_org', 
                            'resolved_ips', 'error']
            else:
                # Registrant lookup mode
                fieldnames = ['input', 'type', 'valid_format', 'registrant', 
                            'whois_org', 'emails', 'registrar', 
                            'creation_date', 'expiration_date', 
                            'name_servers', 'status', 'error']
            
            writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
            writer.writeheader()
            
            for result in results:
                result_copy = result.copy()
                # Convert lists to strings
                for field in ['resolved_ips', 'emails', 'name_servers', 'status']:
                    if field in result_copy and isinstance(result_copy[field], list):
                        result_copy[field] = ', '.join(result_copy[field])
                
                writer.writerow({k: result_copy.get(k, '') for k in fieldnames})
        
        print(f"\nResults written to: {output_file}")
    
    def print_summary(self, results: List[Dict]):
        """Print summary of validation results"""
        total = len(results)
        valid = sum(1 for r in results if r['valid_format'])
        errors = sum(1 for r in results if r.get('error'))
        
        print("\n" + "="*60)
        print("PROCESSING STATISTICS")
        print("="*60)
        print(f"Total entries: {total}")
        print(f"Valid format: {valid}")
        print(f"Errors: {errors}")
        print(f"Timeouts: {self.stats['timeouts']}")
        print(f"Successful lookups: {self.stats['successful']}")
        
        if self.target_org:
            belongs = sum(1 for r in results if r['belongs_to_org'])
            high_conf = sum(1 for r in results if r['confidence'] >= 0.8)
            
            print(f"\nOrganization Matches:")
            print(f"Belongs to '{self.target_org}': {belongs}/{total}")
            print(f"High confidence matches (≥0.8): {high_conf}/{belongs if belongs > 0 else 1}")
            print("="*60)
            
            # Show matches
            if belongs > 0:
                print("\nMATCHED ENTRIES:")
                for r in results:
                    if r['belongs_to_org']:
                        print(f"  ✓ {r['input']} - {r['whois_org'] or 'N/A'} "
                              f"(confidence: {r['confidence']:.1%})")
            
            # Show non-matches
            non_matches = [r for r in results if r['valid_format'] and not r['belongs_to_org'] and not r.get('error')]
            if non_matches:
                print(f"\nNON-MATCHED ENTRIES ({len(non_matches)}):")
                for r in non_matches[:10]:  # Show first 10
                    print(f"  ✗ {r['input']} - {r['whois_org'] or 'Unknown'}")
                if len(non_matches) > 10:
                    print(f"  ... and {len(non_matches) - 10} more")
        else:
            # Registrant lookup mode
            with_org = sum(1 for r in results if r.get('whois_org'))
            with_registrant = sum(1 for r in results if r.get('registrant'))
            
            print(f"\nRegistrant Information:")
            print(f"With organization info: {with_org}/{total}")
            print(f"With registrant info: {with_registrant}/{total}")
            print("="*60)
            
            # Show first few results
            print("\nSAMPLE RESULTS (first 5):")
            for r in results[:5]:
                if r['valid_format'] and not r.get('error'):
                    print(f"\n📍 {r['input']} ({r['type'].upper()})")
                    if r.get('whois_org'):
                        print(f"   Organization: {r['whois_org']}")
                    if r.get('registrant'):
                        print(f"   Registrant: {r['registrant']}")
                    if r.get('registrar'):
                        print(f"   Registrar: {r['registrar']}")
        
        # Show errors
        error_entries = [r for r in results if r.get('error')]
        if error_entries:
            print(f"\nERRORS ({len(error_entries)} entries):")
            for r in error_entries[:5]:
                print(f"  ⚠ {r['input']} - {r['error']}")
            if len(error_entries) > 5:
                print(f"  ... and {len(error_entries) - 5} more errors")


def main():
    parser = argparse.ArgumentParser(
        description='Validate domains/IPs against organization ownership or lookup registrant info',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
EXAMPLES:
=========

1. BASIC REGISTRANT LOOKUP:
   %(prog)s domains.csv                          # Basic lookup
   %(prog)s domains.csv -out results.csv         # Save to CSV

2. ORGANIZATION VALIDATION:
   %(prog)s domains.csv -o "Microsoft"           # Check Microsoft ownership
   %(prog)s domains.csv -o "Google" -v "Alphabet" "YouTube"  # With variations

3. HANDLING TIMEOUTS (for .com.au domains):
   %(prog)s domains.csv --skip-whois --dns-only  # DNS resolution only
   %(prog)s domains.csv --base-domains-only       # Extract base domains
   %(prog)s domains.csv -w 1 --no-batch          # Sequential processing

4. CUSTOM SETTINGS:
   %(prog)s domains.csv --dns-servers 8.8.8.8    # Use Google DNS
   %(prog)s domains.csv -t 30 -w 1               # 30s timeout, 1 worker

INPUT CSV FORMAT:
   domain_or_ip
   google.com
   8.8.8.8
   microsoft.com,azure.com
        """
    )
    
    parser.add_argument('csv_file', help='Input CSV file with domains/IPs')
    parser.add_argument('-o', '--organization',
                       help='Target organization name (if not provided, shows registrant info only)')
    parser.add_argument('-v', '--variations', nargs='*',
                       help='Organization name variations/subsidiaries')
    parser.add_argument('-out', '--output', 
                       help='Output CSV file for results')
    parser.add_argument('-t', '--timeout', type=int, default=WHOIS_TIMEOUT,
                       help=f'Timeout for WHOIS lookups in seconds (default: {WHOIS_TIMEOUT})')
    parser.add_argument('-w', '--workers', type=int, default=MAX_WORKERS,
                       help=f'Number of parallel workers (default: {MAX_WORKERS})')
    parser.add_argument('--no-batch', action='store_true',
                       help='Disable batch processing (process sequentially)')
    parser.add_argument('--skip-dns', action='store_true',
                       help='Skip DNS resolution for domains (faster for large lists)')
    parser.add_argument('--skip-whois', action='store_true',
                       help='Skip WHOIS lookups entirely (for timeout issues)')
    parser.add_argument('--dns-only', action='store_true',
                       help='Only perform DNS lookups, skip WHOIS')
    parser.add_argument('--base-domains-only', action='store_true',
                       help='Extract and lookup base domains only (ignore subdomains)')
    parser.add_argument('--dns-servers', nargs='+',
                       help='Use custom DNS servers (e.g., --dns-servers 8.8.8.8 1.1.1.1)')
    parser.add_argument('--whois-server',
                       help='Use custom WHOIS server (e.g., --whois-server whois.apnic.net)')
    
    args = parser.parse_args()
    
    # Validate conflicting options
    if args.skip_whois and args.dns_only:
        print("Warning: Both --skip-whois and --dns-only specified, using --dns-only")
        args.skip_whois = False
    
    # Store additional flags
    if hasattr(args, 'skip_dns'):
        OrganizationValidator.skip_dns = args.skip_dns
    if hasattr(args, 'base_domains_only'):
        OrganizationValidator.base_domains_only = args.base_domains_only
    
    # Create validator
    validator = OrganizationValidator(
        target_org=args.organization,
        org_variations=args.variations,
        timeout=args.timeout,
        max_workers=args.workers,
        dns_servers=args.dns_servers,
        skip_whois=args.skip_whois,
        dns_only=args.dns_only,
        whois_server=args.whois_server
    )
    
    if args.organization:
        print(f"Validating against organization: {args.organization}")
        if args.variations:
            print(f"Including variations: {', '.join(args.variations)}")
    else:
        if args.dns_only:
            print("DNS lookup mode (no WHOIS)")
        elif args.skip_whois:
            print("WHOIS disabled - showing format validation only")
        else:
            print("Registrant lookup mode (no organization specified)")
    
    print(f"Processing file: {args.csv_file}")
    print(f"Timeout: {args.timeout}s | Workers: {args.workers}")
    
    if args.base_domains_only:
        print("Extracting base domains from subdomains")
    if args.skip_dns:
        print("DNS resolution disabled")
    
    print("-" * 60)
    
    # Process CSV
    try:
        start_time = time.time()
        results = validator.process_csv(
            args.csv_file, 
            args.output,
            batch_mode=not args.no_batch
        )
        elapsed = time.time() - start_time
        
        validator.print_summary(results)
        print(f"\nProcessing completed in {elapsed:.1f} seconds")
        if results:
            print(f"Average: {elapsed/len(results):.2f} seconds per entry")
        
    except FileNotFoundError:
        print(f"Error: File '{args.csv_file}' not found")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n\nInterrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"Error processing file: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()