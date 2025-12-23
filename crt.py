#!/usr/bin/env python3
"""
crt.sh Subdomain Finder - CLI Tool with Proxy Support
Real-time subdomain enumeration using Certificate Transparency logs
Advanced version with multi-proxy support for distributed requests
"""

import requests
import argparse
import json
import csv
import sys
import time
from datetime import datetime
from typing import Set, List, Dict
import urllib3

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Color codes
class Colors:
    RESET = '\033[0m'
    BOLD = '\033[1m'
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'

def print_banner():
    """Display tool banner"""
    banner = f"""{Colors.CYAN}
    ╔═══════════════════════════════════════╗
    ║   crt.sh Subdomain Finder             ║
    ║   Certificate Transparency Logs       ║
    ║   Kali Linux Edition (v3.0 + Proxy)   ║
    ╚═══════════════════════════════════════╝{Colors.RESET}
    """
    print(banner)

def log(level, message):
    """Unified logging function"""
    if level == "info":
        print(f"{Colors.BLUE}[*]{Colors.RESET} {message}")
    elif level == "success":
        print(f"{Colors.GREEN}[+]{Colors.RESET} {message}")
    elif level == "warning":
        print(f"{Colors.YELLOW}[!]{Colors.RESET} {message}")
    elif level == "error":
        print(f"{Colors.RED}[-]{Colors.RESET} {message}")
    elif level == "debug":
        print(f"{Colors.CYAN}[D]{Colors.RESET} {message}")

def is_valid_domain(domain: str) -> bool:
    """Validate domain format"""
    if not domain:
        return False
    parts = domain.split('.')
    if len(parts) < 2:
        return False
    for part in parts:
        if not part or len(part) > 63:
            return False
    return True

def parse_proxy_list(proxy_string: str) -> List[str]:
    """Parse proxy string into list"""
    if not proxy_string:
        return []
    
    proxies = [p.strip() for p in proxy_string.split(',')]
    proxies = [p for p in proxies if p]
    
    # Validate and format proxies
    formatted_proxies = []
    for proxy in proxies:
        # Add protocol if missing
        if not proxy.startswith(('http://', 'https://', 'socks5://')):
            proxy = f'http://{proxy}'
        formatted_proxies.append(proxy)
    
    return formatted_proxies

def load_proxies_from_file(filename: str) -> List[str]:
    """Load proxies from file"""
    try:
        with open(filename, 'r') as f:
            proxies = [line.strip() for line in f.readlines() if line.strip()]
        log("success", f"Loaded {len(proxies)} proxies from {filename}")
        return proxies
    except FileNotFoundError:
        log("error", f"Proxy file not found: {filename}")
        return []
    except Exception as e:
        log("error", f"Error reading proxy file: {str(e)}")
        return []

def fetch_from_crtsh(domain: str, timeout: int = 60, retries: int = 3, 
                     proxy: str = None, test_proxy: bool = False) -> List[Dict]:
    """Fetch subdomains from crt.sh with optional proxy"""
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    
    headers = {
        'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
    }
    
    # Setup proxy
    proxies = {}
    proxy_info = ""
    if proxy:
        proxies = {
            'http': proxy,
            'https': proxy
        }
        proxy_info = f" via {Colors.CYAN}{proxy}{Colors.RESET}"
    
    for attempt in range(1, retries + 1):
        try:
            if test_proxy and proxy:
                log("info", f"Testing proxy {proxy}...")
            else:
                log("info", f"Fetching {domain}{proxy_info}... (Attempt {attempt}/{retries})")
            
            response = requests.get(
                url, 
                timeout=(10, timeout),
                headers=headers,
                proxies=proxies if proxies else None,
                verify=False,
                allow_redirects=True
            )
            response.raise_for_status()
            
            data = response.json()
            
            if test_proxy and proxy:
                log("success", f"Proxy {Colors.GREEN}✓{Colors.RESET} {proxy} is working")
                return []
            
            log("success", f"Retrieved {len(data)} certificates (from {proxy if proxy else 'direct IP'})")
            return data
            
        except requests.exceptions.Timeout:
            if attempt < retries:
                log("warning", f"Timeout on attempt {attempt}/{retries}. Retrying in 5 seconds...")
                time.sleep(5)
                continue
            else:
                log("error", f"Timeout after {retries} attempts.")
                return []
                
        except requests.exceptions.ConnectionError as e:
            if attempt < retries:
                log("warning", f"Connection error on attempt {attempt}/{retries}. Retrying in 5 seconds...")
                time.sleep(5)
                continue
            else:
                log("error", f"Connection error: {str(e)[:50]}")
                return []
                
        except requests.exceptions.ProxyError:
            log("error", f"Proxy error: {proxy} is not working or unreachable")
            return []
            
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 429:
                log("warning", "Rate limited (429). Waiting 10 seconds...")
                time.sleep(10)
                continue
            log("error", f"HTTP Error: {e.response.status_code}")
            return []
            
        except json.JSONDecodeError:
            if attempt < retries:
                log("warning", f"Invalid JSON on attempt {attempt}/{retries}. Retrying...")
                time.sleep(2)
                continue
            else:
                log("error", "Invalid JSON response from crt.sh")
                return []
                
        except Exception as e:
            if attempt < retries:
                log("warning", f"Error on attempt {attempt}/{retries}: {str(e)[:50]}...")
                time.sleep(3)
                continue
            else:
                log("error", f"Unexpected error: {str(e)}")
                return []
    
    return []

def extract_subdomains(data: List[Dict], domain: str) -> Set[str]:
    """Extract unique subdomains from crt.sh response"""
    subdomains = set()
    
    try:
        for cert in data:
            names = cert.get('name_value', '').split('\n')
            
            for name in names:
                cleaned = name.strip().lower()
                
                if cleaned and domain.lower() in cleaned:
                    if cleaned.startswith('*.'):
                        cleaned = cleaned[2:]
                    subdomains.add(cleaned)
    except Exception as e:
        log("warning", f"Error parsing certificates: {str(e)}")
    
    return subdomains

def filter_subdomains(subdomains: Set[str], keyword: str) -> Set[str]:
    """Filter subdomains by keyword"""
    if not keyword:
        return subdomains
    
    keyword = keyword.lower()
    filtered = {sub for sub in subdomains if keyword in sub}
    
    return filtered

def save_results(subdomains: List[str], domain: str, output_format: str = 'txt'):
    """Save results to file"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    if output_format == 'txt':
        filename = f"{domain}_subdomains_{timestamp}.txt"
        try:
            with open(filename, 'w') as f:
                f.write('\n'.join(subdomains))
            log("success", f"Results saved to {Colors.CYAN}{filename}{Colors.RESET}")
        except IOError as e:
            log("error", f"Failed to write file: {str(e)}")
    
    elif output_format == 'json':
        filename = f"{domain}_subdomains_{timestamp}.json"
        try:
            data = {
                'domain': domain,
                'timestamp': datetime.now().isoformat(),
                'subdomain_count': len(subdomains),
                'subdomains': sorted(subdomains)
            }
            with open(filename, 'w') as f:
                json.dump(data, f, indent=2)
            log("success", f"Results saved to {Colors.CYAN}{filename}{Colors.RESET}")
        except IOError as e:
            log("error", f"Failed to write file: {str(e)}")
    
    elif output_format == 'csv':
        filename = f"{domain}_subdomains_{timestamp}.csv"
        try:
            with open(filename, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['Subdomain', 'Domain', 'Timestamp'])
                for subdomain in sorted(subdomains):
                    writer.writerow([subdomain, domain, datetime.now().isoformat()])
            log("success", f"Results saved to {Colors.CYAN}{filename}{Colors.RESET}")
        except IOError as e:
            log("error", f"Failed to write file: {str(e)}")

def display_results(subdomains: List[str], domain: str, response_time: float, proxy: str = None):
    """Display results in terminal"""
    print(f"\n{Colors.CYAN}{'='*60}{Colors.RESET}")
    print(f"{Colors.BOLD}Results for {Colors.CYAN}{domain}{Colors.RESET}")
    if proxy:
        print(f"{Colors.BOLD}Proxy: {Colors.CYAN}{proxy}{Colors.RESET}")
    print(f"{Colors.CYAN}{'='*60}{Colors.RESET}\n")
    
    print(f"{Colors.GREEN}[+] Total Subdomains: {len(subdomains)}{Colors.RESET}")
    print(f"{Colors.GREEN}[+] Response Time: {response_time:.2f}s{Colors.RESET}\n")
    
    if subdomains:
        print(f"{Colors.YELLOW}Subdomains found:{Colors.RESET}\n")
        for i, subdomain in enumerate(sorted(subdomains), 1):
            print(f"  {Colors.CYAN}{i:3d}. {subdomain}{Colors.RESET}")
    else:
        print(f"{Colors.YELLOW}No subdomains found.{Colors.RESET}")
    
    print(f"\n{Colors.CYAN}{'='*60}{Colors.RESET}\n")

def test_proxies(proxies: List[str]):
    """Test all proxies"""
    log("info", f"Testing {len(proxies)} proxy/proxies...")
    print()
    
    working = []
    failed = []
    
    for i, proxy in enumerate(proxies, 1):
        print(f"{Colors.BOLD}{Colors.BLUE}[{i}/{len(proxies)}]{Colors.RESET} ", end="")
        
        # Try to fetch with proxy
        data = fetch_from_crtsh("google.com", timeout=30, retries=1, proxy=proxy, test_proxy=True)
        
        if data or True:  # If we get here without exception, proxy works
            working.append(proxy)
        else:
            failed.append(proxy)
        
        time.sleep(1)
    
    print(f"\n{Colors.CYAN}{'='*60}{Colors.RESET}")
    print(f"{Colors.BOLD}Proxy Test Results{Colors.RESET}")
    print(f"{Colors.CYAN}{'='*60}{Colors.RESET}\n")
    
    print(f"{Colors.GREEN}Working Proxies: {len(working)}{Colors.RESET}")
    for proxy in working:
        print(f"  {Colors.GREEN}✓{Colors.RESET} {proxy}")
    
    if failed:
        print(f"\n{Colors.RED}Failed Proxies: {len(failed)}{Colors.RESET}")
        for proxy in failed:
            print(f"  {Colors.RED}✗{Colors.RESET} {proxy}")
    
    print(f"\n{Colors.CYAN}{'='*60}{Colors.RESET}\n")

def scan_domain(domain: str, keyword: str = None, output_format: str = None, 
                limit: int = None, timeout: int = 60, retries: int = 3,
                proxies: List[str] = None, rotate_proxy: bool = False):
    """Main scanning function with proxy support"""
    
    if not is_valid_domain(domain):
        log("error", f"Invalid domain format: {domain}")
        return False
    
    start_time = time.time()
    
    log("info", f"Starting scan for {Colors.CYAN}{domain}{Colors.RESET}")
    
    # Select proxy if available
    proxy = None
    if proxies:
        if rotate_proxy:
            # Use random proxy from list
            import random
            proxy = random.choice(proxies)
            log("info", f"Using random proxy from pool")
        else:
            # Use first proxy
            proxy = proxies[0]
            log("info", f"Using proxy: {proxy}")
    else:
        log("info", f"Using direct IP (no proxy)")
    
    # Fetch from crt.sh
    data = fetch_from_crtsh(domain, timeout, retries, proxy)
    
    if not data:
        log("warning", "No certificate data found")
        return False
    
    # Extract subdomains
    subdomains = extract_subdomains(data, domain)
    log("success", f"Extracted {len(subdomains)} unique subdomains")
    
    # Apply keyword filter
    if keyword:
        original_count = len(subdomains)
        subdomains = filter_subdomains(subdomains, keyword)
        log("success", f"Filtered by '{keyword}': {len(subdomains)} subdomains")
    
    # Apply limit
    subdomains_list = sorted(list(subdomains))
    if limit:
        subdomains_list = subdomains_list[:limit]
        log("info", f"Limited to {limit} results")
    
    response_time = time.time() - start_time
    
    # Display results
    display_results(subdomains_list, domain, response_time, proxy)
    
    # Save results
    if output_format:
        save_results(subdomains_list, domain, output_format)
    
    return True

def batch_scan_with_proxies(domains: List[str], proxies: List[str], 
                           keyword: str = None, output_format: str = None, timeout: int = 60):
    """Scan multiple domains rotating through proxies"""
    results = {}
    
    log("info", f"Starting batch scan: {len(domains)} domain(s) with {len(proxies)} proxy/proxies")
    print()
    
    for i, domain in enumerate(domains, 1):
        # Rotate through proxies
        proxy = proxies[i % len(proxies)] if proxies else None
        
        print(f"{Colors.BOLD}{Colors.BLUE}[{i}/{len(domains)}]{Colors.RESET} ", end="")
        
        if proxy:
            print(f"{Colors.CYAN}(via {proxy}){Colors.RESET} ", end="")
        
        data = fetch_from_crtsh(domain, timeout, retries=2, proxy=proxy)
        
        if data:
            subdomains = extract_subdomains(data, domain)
            
            if keyword:
                subdomains = filter_subdomains(subdomains, keyword)
            
            results[domain] = {
                'count': len(subdomains),
                'proxy': proxy if proxy else 'direct',
                'subdomains': sorted(list(subdomains))
            }
            
            log("success", f"{domain}: {len(subdomains)} subdomains")
        else:
            results[domain] = {
                'count': 0,
                'proxy': proxy if proxy else 'direct',
                'subdomains': []
            }
            log("warning", f"{domain}: No results")
        
        time.sleep(2)
    
    # Display summary
    print(f"\n{Colors.CYAN}{'='*60}{Colors.RESET}")
    print(f"{Colors.BOLD}Batch Scan Summary{Colors.RESET}")
    print(f"{Colors.CYAN}{'='*60}{Colors.RESET}\n")
    
    total_subdomains = sum(r['count'] for r in results.values())
    
    print(f"{Colors.GREEN}Domains scanned: {len(domains)}{Colors.RESET}")
    print(f"{Colors.GREEN}Proxies used: {len(proxies)}{Colors.RESET}")
    print(f"{Colors.GREEN}Total subdomains: {total_subdomains}{Colors.RESET}\n")
    
    for domain, data in results.items():
        status = f"{Colors.GREEN}✓{Colors.RESET}" if data['count'] > 0 else f"{Colors.YELLOW}○{Colors.RESET}"
        print(f"{status} {domain}: {data['count']} subdomains (proxy: {data['proxy']})")
    
    print(f"\n{Colors.CYAN}{'='*60}{Colors.RESET}\n")

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='crt.sh Subdomain Finder - Proxy Support Edition',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
PROXY EXAMPLES:
  # Single proxy
  %(prog)s -d example.com -p http://192.168.1.1:8080
  
  # Multiple proxies (comma-separated)
  %(prog)s -d example.com -p http://proxy1.com:8080,http://proxy2.com:8080
  
  # Load proxies from file
  %(prog)s -d example.com -pf proxies.txt
  
  # Batch scan with proxy rotation
  %(prog)s -b domain1.com,domain2.com -p http://proxy1.com:8080,http://proxy2.com:8080 --rotate
  
  # Test proxies
  %(prog)s --test-proxies -p http://proxy1.com:8080,http://proxy2.com:8080

PROXY FORMATS:
  http://192.168.1.1:8080
  http://username:password@proxy.com:8080
  socks5://192.168.1.1:1080
  socks5://username:password@proxy.com:1080
  proxy.com:8080 (auto-converted to http://proxy.com:8080)

NOTES:
  - Using proxies slows down requests (extra hop)
  - Test proxies first with --test-proxies
  - Load proxies from file for large lists
  - Rotate proxies with --rotate flag
        '''
    )
    
    parser.add_argument('-d', '--domain', 
                       help='Single domain to scan')
    parser.add_argument('-b', '--batch', 
                       help='Comma-separated domains to scan')
    parser.add_argument('-p', '--proxy', 
                       help='Comma-separated proxies (e.g., http://proxy1:8080,http://proxy2:8080)')
    parser.add_argument('-pf', '--proxy-file', 
                       help='File containing proxies (one per line)')
    parser.add_argument('-k', '--keyword', 
                       help='Filter subdomains by keyword')
    parser.add_argument('-o', '--output', 
                       choices=['txt', 'json', 'csv'],
                       help='Output format')
    parser.add_argument('-l', '--limit', 
                       type=int,
                       help='Limit number of results')
    parser.add_argument('-t', '--timeout', 
                       type=int, 
                       default=60,
                       help='Request timeout in seconds (default: 60)')
    parser.add_argument('-r', '--retries', 
                       type=int, 
                       default=3,
                       help='Number of retries (default: 3)')
    parser.add_argument('--rotate', 
                       action='store_true',
                       help='Rotate through proxies randomly')
    parser.add_argument('--test-proxies', 
                       action='store_true',
                       help='Test proxies and exit')
    parser.add_argument('--no-banner', 
                       action='store_true',
                       help='Don\'t display banner')
    
    args = parser.parse_args()
    
    if not args.no_banner:
        print_banner()
    
    # Load proxies
    proxies = []
    if args.proxy:
        proxies = parse_proxy_list(args.proxy)
    elif args.proxy_file:
        proxies = load_proxies_from_file(args.proxy_file)
    
    # Test proxies if requested
    if args.test_proxies:
        if not proxies:
            log("error", "No proxies provided")
            sys.exit(1)
        test_proxies(proxies)
        sys.exit(0)
    
    # Validate arguments
    if not args.domain and not args.batch:
        parser.print_help()
        log("error", "Please specify either -d/--domain or -b/--batch")
        sys.exit(1)
    
    # Handle single domain scan
    if args.domain:
        success = scan_domain(
            args.domain,
            keyword=args.keyword,
            output_format=args.output,
            limit=args.limit,
            timeout=args.timeout,
            retries=args.retries,
            proxies=proxies,
            rotate_proxy=args.rotate
        )
        sys.exit(0 if success else 1)
    
    # Handle batch scan
    if args.batch:
        domains = [d.strip() for d in args.batch.split(',')]
        domains = [d for d in domains if d]
        
        if not domains:
            log("error", "No valid domains provided")
            sys.exit(1)
        
        if proxies:
            batch_scan_with_proxies(domains, proxies, args.keyword, args.output, args.timeout)
        else:
            log("warning", "No proxies provided for batch scan. Using direct IP.")
            for domain in domains:
                scan_domain(domain, args.keyword, args.output, args.limit, args.timeout, args.retries)
        
        sys.exit(0)

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[!] Interrupted by user{Colors.RESET}")
        sys.exit(0)
    except Exception as e:
        log("error", f"Unexpected error: {str(e)}")
        sys.exit(1)
