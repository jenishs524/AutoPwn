#!/usr/bin/env python3
"""
================================================================================
  VAPT ENGINE v15.0 - Professional Automated Bug Bounty Framework
  Author: [Your Name]
  
  Modules: DNS Recon, Asynchronous Fuzzing, Secret Extraction, API/IDOR, CORS.
  WARNING: For authorized Bug Bounty and Educational Use ONLY.
================================================================================
"""

import argparse
import socket
import sys
import re
import json
import time
import asyncio
import aiohttp
import concurrent.futures
from datetime import datetime
from urllib.parse import urlparse, parse_qs, urlencode, urljoin
from bs4 import BeautifulSoup
import urllib3

# Suppress SSL warnings for testing self-signed certs
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ==============================================================================
# TERMINAL COLORS
# ==============================================================================
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

# ==============================================================================
# CORE UTILITIES
# ==============================================================================
def show_banner():
    print(rf"""
{Colors.CYAN}{Colors.BOLD}
 __      __  _    _____ _______    _____             _            
 \ \    / / | |  |  __ \__   _|  |  __ \           (_)           
  \ \  / /__| |__| |__) | | |    | |  | | ___ _ __  _ _ __   ___ 
   \ \/ / _ \ '_ \  ___/  | |    | |  | |/ _ \ '_ \| | '_ \ / _ \
    \  /  __/ | | | |     | |    | |__| |  __/ | | | | | | |  __/
     \/ \___|_| |_|_|     |_|    |_____/ \___|_| |_|_|_| |_|\___|
                                                                 
        v15.0 - Automated Bug Bounty Framework
{Colors.END}
""")

def print_section(title):
    print(f"\n{Colors.PURPLE}{'=' * 75}{Colors.END}")
    print(f"{Colors.PURPLE}  {title}{Colors.END}")
    print(f"{Colors.PURPLE}{'=' * 75}{Colors.END}")

async def fetch(session, url, method="GET", data=None):
    try:
        async with session.request(method, url, data=data, timeout=10, ssl=False) as response:
            return await response.text(), response.status, response.headers
    except Exception:
        return "", 0, {}

# ==============================================================================
# MODULE 1: THREADED PORT SCANNER
# ==============================================================================
def port_scan(host, results):
    print_section(f"THREADED PORT SCANNER: {host}")
    ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 8080, 8443]
    open_ports = []
    
    def check_port(port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((host, port))
            sock.close()
            return port if result == 0 else None
        except:
            return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        for res in executor.map(check_port, ports):
            if res:
                open_ports.append(res)
                print(f"{Colors.GREEN}[✓] Port {res} OPEN{Colors.END}")
    
    results['open_ports'] = open_ports

# ==============================================================================
# MODULE 2: DEEP SOURCE CODE ANALYSIS (SECRETS)
# ==============================================================================
def analyze_source(html, url, results):
    print_section("SOURCE CODE ANALYSIS (SECRETS & INFO LEAK)")
    
    # Advanced regex for finding secrets
    patterns = {
        "AWS API Key": r"AKIA[0-9A-Z]{16}",
        "Google API Key": r"AIza[0-9A-Za-z\\-_]{35}",
        "Stripe Live Key": r"sk_live_[0-9a-zA-Z]{24}",
        "Internal IP": r"\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b",
        "Email Address": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,4}\b"
    }
    
    found_any = False
    for name, pattern in patterns.items():
        matches = set(re.findall(pattern, html))
        # Filter out false positive emails (images)
        valid = [m for m in matches if not m.endswith(('.png', '.jpg', '.jpeg', '.gif', '.svg'))]
        
        if valid:
            found_any = True
            for match in list(valid)[:3]:
                print(f"{Colors.RED}[!] Found {name}: {Colors.WHITE}{match}{Colors.END}")
                results['vulnerabilities'].append({
                    "type": f"Sensitive Data Leak: {name}",
                    "severity": "Medium",
                    "evidence": match
                })
    
    if not found_any:
        print(f"{Colors.GREEN}[✓] No obvious API keys or internal IPs found.{Colors.END}")

# ==============================================================================
# MODULE 3: CORS MISCONFIGURATION
# ==============================================================================
async def test_cors(session, url, results):
    print_section("CORS MISCONFIGURATION CHECK")
    try:
        async with session.get(url, headers={"Origin": "https://evil-hacker.com"}, ssl=False) as resp:
            acao = resp.headers.get("Access-Control-Allow-Origin", "")
            acac = resp.headers.get("Access-Control-Allow-Credentials", "")
            
            if "evil-hacker.com" in acao and acac.lower() == "true":
                print(f"{Colors.RED}[!] CRITICAL: CORS Misconfiguration! Reflects evil origin with credentials.{Colors.END}")
                results['vulnerabilities'].append({"type": "CORS Misconfiguration", "severity": "High"})
            else:
                print(f"{Colors.GREEN}[✓] CORS is securely configured.{Colors.END}")
    except:
        pass

# ==============================================================================
# MODULE 4: API DISCOVERY & IDOR
# ==============================================================================
async def test_apis(session, html, url, results):
    print_section("API DISCOVERY & IDOR TESTING")
    
    # Look for API endpoints in the source code
    api_patterns = r'/(api|v1|v2|graphql|rest)/[a-zA-Z0-9_\-/]+'
    apis = set(re.findall(api_patterns, html))
    
    if not apis:
        print(f"{Colors.YELLOW}[!] No API endpoints found in source code.{Colors.END}")
        return
    
    for api in list(apis)[:5]:
        endpoint = urljoin(url, api)
        print(f"{Colors.BLUE}[*] Testing endpoint: {endpoint}{Colors.END}")
        
        # IDOR Check: Try appending IDs
        for test_id in ["/1", "/2", "/admin"]:
            test_url = endpoint + test_id
            r, status, _ = await fetch(session, test_url)
            if status == 200 and len(r) > 50 and "error" not in r.lower():
                print(f"{Colors.RED}[!] POTENTIAL IDOR/BROKEN ACCESS: {test_url} returned data!{Colors.END}")
                results['vulnerabilities'].append({
                    "type": "IDOR / Broken Access Control",
                    "severity": "High",
                    "url": test_url,
                    "evidence": "Appending ID to API returned unauthorized data."
                })

# ==============================================================================
# MODULE 5: ASYNC XSS & SQLi FUZZING
# ==============================================================================
async def fuzz_vulnerabilities(session, urls_to_test, results):
    print_section("ASYNCHRONOUS XSS & SQLi FUZZING")
    
    if not urls_to_test:
        print(f"{Colors.YELLOW}[!] No URLs with parameters found to fuzz.{Colors.END}")
        return

    print(f"{Colors.BLUE}[*] Launching async payloads on {len(urls_to_test)} targets...{Colors.END}")
    found = False
    
    for url in urls_to_test:
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        for param in params:
            # 1. TEST XSS
            xss_payload = '<script>alert("VAPT_POC")</script>'
            test_params = params.copy()
            test_params[param] = [xss_payload]
            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params, doseq=True)}"
            
            resp, _, _ = await fetch(session, test_url)
            if xss_payload in resp:
                found = True
                print(f"{Colors.RED}{Colors.BOLD}[!] CRITICAL: Reflected XSS Found!{Colors.END}")
                print(f"    {Colors.WHITE}PoC URL:{Colors.END} {test_url}")
                results['vulnerabilities'].append({"type": "Reflected XSS", "severity": "High", "url": test_url})
                
            # 2. TEST SQLi
            sqli_payload = "'"
            test_params[param] = [sqli_payload]
            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params, doseq=True)}"
            
            resp, _, _ = await fetch(session, test_url)
            if re.search(r"SQL syntax.*MySQL|Warning.*mysql_|PostgreSQL.*ERROR|ORA-[0-9]{4,5}", resp, re.IGNORECASE):
                found = True
                print(f"{Colors.RED}{Colors.BOLD}[!] CRITICAL: Error-Based SQL Injection Found!{Colors.END}")
                print(f"    {Colors.WHITE}PoC URL:{Colors.END} {test_url}")
                results['vulnerabilities'].append({"type": "SQL Injection", "severity": "Critical", "url": test_url})

    if not found:
        print(f"{Colors.GREEN}[✓] Fuzzing complete. Target appears secure.{Colors.END}")

# ==============================================================================
# MAIN ORCHESTRATOR
# ==============================================================================
async def run_engine(domain, results):
    base_url = f"http://{domain}"
    
    async with aiohttp.ClientSession() as session:
        print_section(f"FETCHING TARGET: {base_url}")
        html, status, headers = await fetch(session, base_url)
        
        if not html:
            print(f"{Colors.RED}[✗] Failed to connect to {base_url}.{Colors.END}")
            return
        
        print(f"{Colors.GREEN}[✓] Page downloaded ({len(html)} bytes).{Colors.END}")
        
        # Execute Modules
        analyze_source(html, base_url, results)
        await test_cors(session, base_url, results)
        await test_apis(session, html, base_url, results)
        
        # Deep Crawl
        print_section("DEEP CRAWLING FOR PARAMETERS")
        soup = BeautifulSoup(html, 'html.parser')
        urls_to_test = set()
        for a in soup.find_all('a', href=True):
            link = urljoin(base_url, a['href'])
            if domain in link and "?" in link and "=" in link:
                urls_to_test.add(link)
                
        print(f"{Colors.GREEN}[✓] Discovered {len(urls_to_test)} dynamic URLs.{Colors.END}")
        
        await fuzz_vulnerabilities(session, list(urls_to_test)[:10], results)

def main():
    show_banner()
    parser = argparse.ArgumentParser()
    parser.add_argument("-u", "--url", required=True, help="Target URL (e.g. testphp.vulnweb.com)")
    args = parser.parse_args()
    
    domain = urlparse(args.url).hostname if args.url.startswith(('http', 'https')) else args.url
    print(f"{Colors.YELLOW}[*] Target: {domain}{Colors.END}")
    
    results = {"target": domain, "time": str(datetime.now()), "vulnerabilities": []}
    
    # 1. Run Port Scan (Synchronous)
    port_scan(domain, results)
    
    # 2. Run Web Modules (Asynchronous)
    try:
        asyncio.run(run_engine(domain, results))
    except KeyboardInterrupt:
        print(f"\n{Colors.RED}[!] Interrupted by user.{Colors.END}")
        
    # 3. Save Report
    filename = f"VAPT_Report_{domain.replace('.', '_')}.json"
    with open(filename, 'w') as f:
        json.dump(results, f, indent=4)
    print(f"\n{Colors.GREEN}{Colors.BOLD}[✓] FINAL REPORT SAVED: {filename}{Colors.END}")

if __name__ == "__main__":
    main()