# Vuln
Advanced Vulnerability Scanner (Educational Use Only)
This project is a minimalist, extensible vulnerability scanner framework designed for learning and authorized security testing. It combines multiple modules into a single CLI tool that can be run against a target host or URL. The scanner is lightweight, written in Python, and outputs structured JSON reports with clear summaries.
✨ Features
• 	Port Scanning – Detects open TCP ports using sockets (optional Nmap integration if installed).
• 	Service Fingerprinting – Grabs banners and identifies common services (Apache, nginx, MySQL, etc.).
• 	Header Analysis – Checks for missing security headers (CSP, HSTS, X-Frame-Options, etc.).
• 	SSL/TLS Checks – Inspects certificates, expiry dates, and weak protocol support.
• 	Web Vulnerability Scan – Heuristic detection of query parameters, forms, and optional intrusive tests (SQLi, XSS, directory traversal).
• 	Directory Brute Force – Attempts discovery of common files and directories (, , backups).
• 	CVE Lookup – Queries the NVD API for known vulnerabilities related to detected services.
• 	JSON Reporting – Saves results with timestamps and provides a concise color‑coded summary.

# Disclaimer
This tool is for educational purposes only. Use it only on systems you own or have explicit permission to test. Unauthorized scanning may be illegal.

# Installation
pipx install vuln

# Show version
vuln --version

# Modules
The scanner is modular, meaning you can run all checks or select specific ones using the --modules option.
.Port Scan
. Service Fingerprint 
. Web Vulnerability
. SSL/TLS Checks
. Header Analysis
. Directory Brute Force
. CVE Lookup

# Run a full scan
vuln https://example.com

# Run specific modules
vuln https://example.com --modules port webvuln ssl

# Enable intrusive tests (SQLi/XSS heuristics)
vuln https://example.com --intrusive

# Note 
This is in early phase (ie 1st version). So if you find any error or any suggestion you can contact me nowhere.





