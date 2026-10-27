#!/usr/bin/env python3
"""
================================================================================
  SubHunter v1.0 - Automated Subdomain Takeover Framework
  Author: [Your Name]
  
  Description: Crawls crt.sh for subdomains, resolves their CNAME records, 
  and fingerprints them against known vulnerable cloud services (AWS, GitHub, etc).
  
  WARNING: Use ONLY on domains you own or have explicit permission to test.
================================================================================
"""

import argparse
import socket
import sys
import json
import time
import requests
import dns.resolver
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

# Disable SSL warnings
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    END = '\033[0m'

def show_banner():
    print(rf"""
{Colors.CYAN}{Colors.BOLD}
  _____       _    _            _            
 / ____|     | |  | |          | |           
| (___  _   _| |__| |_   _ _ __ | |_ ___ _ __ 
 \___ \| | | | '_ \ | | | | '_ \| __/ _ \ '__|
 ____) | |_| | |_) | |_| | | | | ||  __/ |   
|_____/ \__,_|_.__/|_|\__,_|_| |_|\__\___|_|   
                                              
        v1.0 - Automated Subdomain Takeover Tool
{Colors.END}
""")

def print_section(title):
    print(f"\n{Colors.PURPLE}{'=' * 65}{Colors.END}")
    print(f"{Colors.PURPLE}  {title}{Colors.END}")
    print(f"{Colors.PURPLE}{'=' * 65}{Colors.END}")

# ==============================================================================
# VULNERABILITY FINGERPRINTS
# ==============================================================================
# If a CNAME points to these services, AND the response body contains the string,
# it means the resource is unclaimed and vulnerable to takeover.
VULNERABLE_SERVICES = {
    "github.io": ["There isn't a GitHub Pages site here"],
    "s3.amazonaws.com": ["NoSuchBucket", "The specified bucket does not exist"],
    "herokuapp.com": ["No such app", "heroku | no such app"],
    "azurewebsites.net": ["404 Web Site not found"],
    "cloudfront.net": ["Bad request", "ERROR: The request could not be satisfied"],
    "bitbucket.io": ["Repository not found"],
    "ghost.io": ["Domain error"],
    "surge.sh": ["project not found"],
    "readme.io": ["Project doesnt exist"],
    "zendesk.com": ["Help Center Closed"],
    "netlify.app": ["Not Found - Request ID"],
    "vercel.app": ["The deployment could not be found"],
    "firebaseapp.com": ["Site Not Found"],
}

# ==============================================================================
# SUBDOMAIN ENUMERATION
# ==============================================================================
def get_subdomains(domain):
    print_section(f"SUBDOMAIN ENUMERATION: {domain}")
    print(f"{Colors.BLUE}[*] Querying crt.sh (Certificate Transparency Logs)...{Colors.END}")
    
    subdomains = set()
    try:
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        response = requests.get(url, timeout=30)
        
        if response.status_code == 200:
            data = response.json()
            for entry in data:
                # Some entries have multiple subdomains separated by newlines
                for sub in entry.get("name_value", "").split("\n"):
                    sub = sub.strip().lower()
                    if sub.endswith(domain) and "*" not in sub:
                        subdomains.add(sub)
    except Exception as e:
        print(f"{Colors.RED}[✗] crt.sh query failed: {e}{Colors.END}")
    
    # Add the root domain just in case
    subdomains.add(domain)
    
    print(f"{Colors.GREEN}[✓] Found {len(subdomains)} unique subdomains.{Colors.END}")
    return list(subdomains)

# ==============================================================================
# TAKEOVER CHECKER ENGINE
# ==============================================================================
def check_subdomain(subdomain):
    """Check a single subdomain for dangling CNAMEs and takeovers."""
    try:
        # 1. Resolve CNAME
        answers = dns.resolver.resolve(subdomain, 'CNAME', lifetime=5)
        for rdata in answers:
            cname = str(rdata.target).lower().rstrip(".")
            
            # 2. Check if CNAME matches a known vulnerable service
            for service, fingerprints in VULNERABLE_SERVICES.items():
                if service in cname:
                    # 3. Fetch the HTTP response to confirm it's unclaimed
                    try:
                        resp = requests.get(f"http://{subdomain}", timeout=10, verify=False)
                        for fp in fingerprints:
                            if fp.lower() in resp.text.lower():
                                return {
                                    "subdomain": subdomain,
                                    "cname": cname,
                                    "service": service,
                                    "status": "VULNERABLE",
                                    "evidence": fp
                                }
                    except requests.exceptions.RequestException:
                        pass
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
        pass # Subdomain has no CNAME or doesn't exist
    except Exception:
        pass
    
    return None

def scan_domain(domain, results):
    subdomains = get_subdomains(domain)
    print_section("CNAME RESOLUTION & TAKEOVER CHECK")
    print(f"{Colors.BLUE}[*] Testing {len(subdomains)} subdomains concurrently...{Colors.END}")
    
    vulnerable_count = 0
    
    with ThreadPoolExecutor(max_workers=20) as executor:
        for result in executor.map(check_subdomain, subdomains):
            if result:
                vulnerable_count += 1
                print(f"\n{Colors.RED}{Colors.BOLD}[!] CRITICAL VULNERABILITY FOUND!{Colors.END}")
                print(f"    {Colors.WHITE}Subdomain:{Colors.END} {result['subdomain']}")
                print(f"    {Colors.WHITE}CNAME:{Colors.END}     {result['cname']}")
                print(f"    {Colors.WHITE}Service:{Colors.END}   {result['service']}")
                print(f"    {Colors.WHITE}Evidence:{Colors.END}  '{result['evidence']}'")
                print(f"    {Colors.YELLOW}EXPLOIT:{Colors.END} Register an account on {result['service']} and claim the name '{result['cname'].split('.')[0]}' to take over this subdomain.")
                
                results['vulnerabilities'].append(result)
    
    if vulnerable_count == 0:
        print(f"\n{Colors.GREEN}[✓] No vulnerable subdomains found. Target is secure.{Colors.END}")

# ==============================================================================
# MAIN
# ==============================================================================
def main():
    show_banner()
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--domain", required=True, help="Target domain (e.g., example.com)")
    args = parser.parse_args()
    
    domain = args.domain.lower()
    print(f"{Colors.YELLOW}[*] Target: {domain}{Colors.END}")
    print(f"{Colors.YELLOW}[*] Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Colors.END}")
    
    results = {
        "target": domain,
        "time": str(datetime.now()),
        "vulnerabilities": []
    }
    
    start_time = time.time()
    scan_domain(domain, results)
    duration = time.time() - start_time
    
    # Save Report
    filename = f"SubHunter_Report_{domain}.json"
    with open(filename, 'w') as f:
        json.dump(results, f, indent=4)
        
    print(f"\n{Colors.GREEN}[✓] Scan completed in {duration:.2f} seconds.{Colors.END}")
    print(f"{Colors.GREEN}[✓] JSON Report saved: {filename}{Colors.END}")

if __name__ == "__main__":
    main()