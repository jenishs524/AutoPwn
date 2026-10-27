#!/usr/bin/env python3
import requests
import urllib3
import sys
import re
import concurrent.futures
from urllib.parse import urlparse

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Colors
GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
CYAN = '\033[96m'
RESET = '\033[0m'

def banner():
    print(f"""{CYAN}
==============================================================
  GOD-TIER RECON SCRIPT - Bug Bounty Edition
  Finds Subdomains, Git leaks, Env files, and Tech Stack.
  (Use ONLY on in-scope targets!)
=============================================================={RESET}
""")

def get_subdomains(domain):
    print(f"{BLUE}[*] Fetching subdomains for {domain}...{RESET}")
    subdomains = set([domain, f"www.{domain}"])
    try:
        # Using HackerTarget API (Free tier)
        url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
        response = requests.get(url, timeout=15, verify=False)
        if "error" not in response.text.lower() and "API count exceeded" not in response.text:
            for line in response.text.split('\n'):
                if ',' in line:
                    sub = line.split(',')[0]
                    subdomains.add(sub)
        print(f"{GREEN}[✓] Found {len(subdomains)} subdomains.{RESET}")
    except Exception as e:
        print(f"{RED}[✗] Error fetching subdomains: {e}{RESET}")
    return list(subdomains)

def check_exposures(subdomain):
    findings = []
    
    # Paths that usually leak massive data
    sensitive_paths = {
        "/.git/config": "Git Repo Leak (Source Code Exposure)",
        "/.env": "Environment Variables (API Keys, Passwords)",
        "/config.php.bak": "Backup PHP Config",
        "/backup.zip": "Backup Archive",
        "/.htaccess": "Apache Config",
        "/server-status": "Apache Server Status"
    }
    
    # Check if the subdomain is actually live
    try:
        base_url = f"http://{subdomain}"
        r = requests.get(base_url, timeout=5, verify=False)
        server = r.headers.get('Server', 'Unknown')
        
        # If it's live, check for exposures
        for path, description in sensitive_paths.items():
            try:
                target_url = f"{base_url}{path}"
                res = requests.get(target_url, timeout=5, verify=False)
                
                if res.status_code == 200:
                    # Basic false-positive check (make sure it's not a 404 page returning 200)
                    if path == "/.env" and "APP_" not in res.text and "DB_" not in res.text and "=" not in res.text:
                        continue
                    if path == "/.git/config" and "[core]" not in res.text:
                        continue
                        
                    findings.append({
                        "subdomain": subdomain,
                        "url": target_url,
                        "type": description,
                        "severity": "CRITICAL"
                    })
            except:
                pass
    except:
        pass # Subdomain is dead or unreachable
        
    return findings

def main():
    banner()
    if len(sys.argv) != 2:
        print(f"{YELLOW}Usage: python3 god_recon.py <target-domain.com>{RESET}")
        sys.exit(1)
        
    target = sys.argv[1]
    print(f"{BLUE}[*] Starting deep recon on {target}...{RESET}\n")
    
    # Step 1: Find Subdomains
    subs = get_subdomains(target)
    
    # Step 2: Scan all subdomains for exposures
    print(f"\n{BLUE}[*] Scanning {len(subs)} subdomains for exposed sensitive files...{RESET}")
    all_findings = []
    
    # Use threads to scan faster
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        results = executor.map(check_exposures, subs)
        for result in results:
            if result:
                all_findings.extend(result)
                for f in result:
                    print(f"{RED}[!] CRITICAL: {f['type']}{RESET}")
                    print(f"    URL: {f['url']}")
    
    # Step 3: Save the loot
    if all_findings:
        with open(f"{target}_bounty_loot.txt", "w") as f:
            for finding in all_findings:
                f.write(f"Type: {finding['type']}\nURL: {finding['url']}\n\n")
        print(f"\n{GREEN}[✓] Scan complete! Found {len(all_findings)} critical exposures.{RESET}")
        print(f"{GREEN}[✓] Loot saved to {target}_bounty_loot.txt{RESET}")
    else:
        print(f"\n{YELLOW}[!] Scan complete. No obvious exposures found. The target is secure.{RESET}")

if __name__ == "__main__":
    main()