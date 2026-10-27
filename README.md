# SubHunter v1.0 - Subdomain Takeover Framework

An advanced automated bug bounty tool that discovers subdomains via crt.sh and checks for dangling CNAME records that can be hijacked.

## Features
- **Passive Recon:** Fetches subdomains from Certificate Transparency logs (crt.sh).
- **CNAME Resolution:** Automatically resolves CNAME records for all found subdomains.
- **Fingerprinting Engine:** Checks if the CNAME points to 15+ vulnerable cloud services (AWS S3, GitHub Pages, Heroku, Azure, etc.).
- **Auto-Verification:** Fetches the HTTP response to confirm if the cloud resource is actually unclaimed.
- **JSON Reporting:** Generates a professional report with exploit instructions.

## Installation
```bash
git clone https://github.com/YOUR-USERNAME/SubHunter.git
cd SubHunter
pip install -r requirements.txt