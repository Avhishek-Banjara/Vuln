from __future__ import annotations
import socket
import ssl
import sys
import json
import time
import re
import subprocess
from datetime import datetime
from typing import List, Dict, Any, Optional
import requests
from colorama import init as colorama_init, Fore, Style
import sys
import socket
import ssl
import json
import subprocess
import threading
import time
from datetime import datetime
from urllib.parse import urlparse, urljoin, parse_qs
import requests
from collections import defaultdict
from colorama import init as colorama_init, Fore, Style

#!/usr/bin/env python3
"""
hoho.py -- Minimalist, extensible vulnerability scanner framework (for authorized testing only)

Usage: run in terminal. Prompts for a target (IP or URL) and offers module choices.
Each module is modular and returns structured findings. Results saved to JSON.

Important: Use only on systems/targets you own or have explicit permission to test.
"""


# Third-party libs; we try to import and guide user if missing.
try:
    import requests
except Exception:
    print("Missing dependency: requests. Install with: pip install requests")
    sys.exit(1)

try:
    from colorama import init as colorama_init, Fore, Style
except Exception:
    print("Missing dependency: colorama. Install with: pip install colorama")
    sys.exit(1)

colorama_init(autoreset=True)

# Constants & severity mapping
SEVERITY = ["Info", "Low", "Medium", "High", "Critical"]
DEFAULT_PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 3306, 3389, 8080]

# Simple fingerprints mapping (expandable)
FINGERPRINT_PATTERNS = {
    "Apache": re.compile(r"Apache/?\s*([0-9\.]*)", re.I),
    "nginx": re.compile(r"nginx/?\s*([0-9\.]*)", re.I),
    "OpenSSH": re.compile(r"OpenSSH_([0-9\.]+)"),
    "Postgres": re.compile(r"PostgreSQL\s*([0-9\.]+)"),
    "MySQL": re.compile(r"MySQL\s*([0-9\.]+)|mysql_native_password", re.I),
    "IIS": re.compile(r"Microsoft-IIS/?\s*([0-9\.]*)", re.I),
}

# Helper printing
def info(msg: str):
    print(Fore.CYAN + "[*] " + msg)

def ok(msg: str):
    print(Fore.GREEN + "[+] " + msg)

def warn(msg: str):
    print(Fore.YELLOW + "[-] " + msg)

def err(msg: str):
    print(Fore.RED + "[!] " + msg)

# Utilities
def normalize_target(raw: str) -> str:
    raw = raw.strip()
    if raw.startswith("http://") or raw.startswith("https://"):
        return raw
    # treat as hostname/IP -> default to http
    return "http://" + raw

def safe_request(method: str, url: str, **kwargs) -> Optional[requests.Response]:
    try:
        return requests.request(method, url, timeout=8, allow_redirects=True, verify=False, **kwargs)
    except Exception:
        return None

# Module: Port scanner (socket-based)
def port_scan(host: str, ports: List[int] = DEFAULT_PORTS, timeout: float = 1.0) -> Dict[int, str]:
    results: Dict[int, str] = {}
    info(f"Starting port scan on {host}")
    for port in ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                res = s.connect_ex((host, port))
                if res == 0:
                    # attempt banner grab
                    banner = ""
                    try:
                        s.settimeout(1.0)
                        s.sendall(b"\r\n")
                        banner = s.recv(1024).decode(errors="ignore").strip()
                    except Exception:
                        banner = ""
                    results[port] = banner or "open"
                    ok(f"Port {port}/tcp open")
                else:
                    info(f"Port {port}/tcp closed")
        except Exception as ex:
            warn(f"Port {port} scan error: {ex}")
            continue
    return results

# Optional nmap integration
def nmap_scan(target: str, args: str = "-sV -Pn -T4") -> Optional[str]:
    try:
        out = subprocess.check_output(["nmap", *args.split(), target], stderr=subprocess.STDOUT, text=True, timeout=120)
        return out
    except Exception as e:
        print_err(f"nmap scan failed: {e}")
        return None

# Notes:
# - This tool performs benign checks by default. Enable intrusive tests when you
#   have explicit permission to scan the target (legal requirement).
# - Requires: requests, colorama
#   Install: pip install requests colorama


colorama_init(autoreset=True)

# -----------------------
# Utility & config
# -----------------------
DEFAULT_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 3389, 3306, 8080]
DEFAULT_WORDLIST = ["admin", "login", "robots.txt", "sitemap.xml", "backup", "backup.zip", "test", "old", "config", ".env"]
TIMEOUT = 3  # socket / request timeout in seconds

def print_status(msg, color=Fore.CYAN):
    print(color + msg + Style.RESET_ALL)

def print_ok(msg):
    print_status(msg, Fore.GREEN)

def print_warn(msg):
    print_status(msg, Fore.YELLOW)

def print_err(msg):
    print_status(msg, Fore.RED)

def severity_from_score(score):
    # score: 0-100 heuristic
    if score >= 80:
        return "Critical"
    if score >= 60:
        return "High"
    if score >= 30:
        return "Medium"
    return "Low"

# -----------------------
# Target parsing
# -----------------------
def normalize_target(raw):
    raw = raw.strip()
    if not raw:
        raise ValueError("Empty target")
    if raw.startswith("http://") or raw.startswith("https://"):
        parsed = urlparse(raw)
        host = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        base = f"{parsed.scheme}://{parsed.netloc}"
        return {"host": host, "port": port, "url": base}
    # if IP or host
    if ":" in raw:
        host, port = raw.split(":", 1)
        try:
            port = int(port)
        except:
            port = 80
    else:
        host = raw
        port = 80
    return {"host": host, "port": port, "url": f"http://{host}:{port}"}

# -----------------------
# Port scanner (socket-based, optional nmap)
# -----------------------
def port_scan_socket(host, ports=DEFAULT_PORTS, timeout=TIMEOUT):
    results = {}
    def scan_port(p):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                r = s.connect_ex((host, p))
                results[p] = ("open" if r == 0 else "closed")
        except Exception as e:
            results[p] = f"error:{e}"
    threads = []
    for p in ports:
        t = threading.Thread(target=scan_port, args=(p,))
        t.start()
        threads.append(t)
    for t in threads:
        t.join()
    return results

def port_scan_nmap(host):
    # try to use nmap if installed; returns raw output
    try:
        proc = subprocess.run(["nmap", "-sV", host], capture_output=True, text=True, timeout=60)
        return {"nmap_output": proc.stdout}
    except Exception as e:
        return {"nmap_error": str(e)}

# -----------------------
# Service fingerprinting
# -----------------------
def banner_grab(host, port, timeout=TIMEOUT):
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.settimeout(timeout)
        try:
            s.sendall(b"\r\n")
        except:
            pass
        try:
            data = s.recv(1024)
        except:
            data = b""
        s.close()
        return data.decode(errors="ignore").strip()
    except Exception as e:
        return f"error: {e}"

def service_fingerprint(target_info, open_ports):
    host = target_info["host"]
    findings = {}
    # grab banners for open ports
    for p, state in open_ports.items():
        if state != "open":
            continue
        try:
            b = banner_grab(host, p)
            findings[p] = {"banner": b}
        except Exception as e:
            findings[p] = {"error": str(e)}
    # HTTP(S) server header
    try:
        url = target_info["url"]
        r = requests.get(url, timeout=TIMEOUT, allow_redirects=True)
        server = r.headers.get("Server", "")
        findings["http_server_header"] = server
    except Exception:
        findings["http_server_header"] = None
    return findings

# -----------------------
# Header analysis
# -----------------------
SECURITY_HEADERS = ["Content-Security-Policy", "Strict-Transport-Security", "X-Frame-Options", "X-Content-Type-Options", "Referrer-Policy", "Permissions-Policy"]

def header_analysis(url):
    res = {"present": {}, "missing": []}
    try:
        r = requests.get(url, timeout=TIMEOUT, allow_redirects=True)
        for h in SECURITY_HEADERS:
            if h in r.headers:
                res["present"][h] = r.headers.get(h)
            else:
                res["missing"].append(h)
        res["status_code"] = r.status_code
    except Exception as e:
        res["error"] = str(e)
    return res

# -----------------------
# SSL/TLS checks
# -----------------------
def ssl_scan(host, port=443):
    out = {}
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=host) as s:
            s.settimeout(TIMEOUT)
            s.connect((host, port))
            cert = s.getpeercert()
            out["cert_subject"] = dict(x[0] for x in cert.get("subject", ()))
            out["issuer"] = dict(x[0] for x in cert.get("issuer", ()))
            # expiry
            if "notAfter" in cert:
                expiry_str = cert["notAfter"]
                expiry_dt = datetime.strptime(expiry_str, "%b %d %H:%M:%S %Y %Z")
                out["notAfter"] = expiry_str
                out["expired"] = expiry_dt < datetime.utcnow()
            else:
                out["notAfter"] = None
            s.close()
    except Exception as e:
        out["error"] = str(e)
    # Check for old protocol support (non-exhaustive)
    proto_support = {}
    for proto_name, proto in [("SSLv3", ssl.PROTOCOL_TLSv1), ("TLSv1", ssl.PROTOCOL_TLSv1), ("TLSv1_1", getattr(ssl, "PROTOCOL_TLSv1_1", None)), ("TLSv1_2", getattr(ssl, "PROTOCOL_TLSv1_2", None))]:
        if proto is None:
            continue
        try:
            ctx = ssl.SSLContext(proto)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with ctx.wrap_socket(socket.socket(), server_hostname=host) as s:
                s.settimeout(TIMEOUT)
                s.connect((host, port))
                proto_support[proto_name] = True
                s.close()
        except Exception:
            proto_support[proto_name] = False
    out["protocol_support"] = proto_support
    return out

# -----------------------
# Basic web vulnerability checks (non-intrusive by default)
# -----------------------
def find_forms(html):
    # Minimal form detection (beginner-friendly)
    forms = []
    pos = 0
    lower = html.lower()
    while True:
        idx = lower.find("<form", pos)
        if idx == -1:
            break
        end = lower.find(">", idx)
        if end == -1:
            break
        # find form end
        close = lower.find("</form>", end)
        if close == -1:
            form_html = html[idx:end+1]
            pos = end+1
        else:
            form_html = html[idx:close+7]
            pos = close + 7
        forms.append(form_html)
    return forms

def basic_web_vuln_scan(url, intrusive=False):
    findings = []
    try:
        r = requests.get(url, timeout=TIMEOUT)
        html = r.text
    except Exception as e:
        return {"error": str(e)}

    # discover query parameters in landing URL
    parsed = urlparse(url)
    qs = parse_qs(parsed.query)
    if qs:
        findings.append({"issue": "Query parameters found", "details": list(qs.keys()), "severity": "Low", "recommendation": "Validate and sanitize query parameters."})

    # forms
    forms = find_forms(html)
    if forms:
        findings.append({"issue": "Forms detected", "details": f"{len(forms)} form(s) discovered", "severity": "Low", "recommendation": "Ensure server-side validation and escaping."})

    # if intrusive, perform simple payload tests (use only with permission)
    if intrusive:
        # SQLi heuristic: append a single-quote to common URL param and observe changes
        try:
            if not qs:
                # attempt to find a simple parameter by crawling links
                # grab first href with ?param=value
                links = []
                for part in html.split("href=")[1:]:
                    q = part.split()[0].strip("\"'<>")
                    if "?" in q:
                        links.append(q)
                if links:
                    test_url = urljoin(url, links[0])
                else:
                    test_url = url
            else:
                # append to first param
                first_param = list(qs.keys())[0]
                base = parsed._replace(query="").geturl()
                test_url = f"{base}?{first_param}=test'"
            r1 = requests.get(test_url, timeout=TIMEOUT)
            # check typical SQL error signatures
            errors = ["sql syntax", "mysql", "syntax to use", "unterminated quoted string", "mssql", "odbc"]
            if any(e in r1.text.lower() for e in errors) or r1.status_code >= 500:
                findings.append({"issue": "Possible SQL Injection (heuristic)", "details": test_url, "severity": "High", "recommendation": "Review query handling and use parameterized queries."})
        except Exception as e:
            findings.append({"issue": "SQLi test failed", "details": str(e), "severity": "Low"})

        # XSS heuristic: inject a benign payload that will appear in response
        try:
            payload = "<script>alert(1)</script>"
            if not qs:
                # try simple param injection into path
                test_url = urljoin(url, f"/{payload}")
                r2 = requests.get(test_url, timeout=TIMEOUT)
                if payload in r2.text:
                    findings.append({"issue": "Reflected XSS (heuristic)", "details": test_url, "severity": "High", "recommendation": "Output-encode user-supplied content."})
            else:
                first_param = list(qs.keys())[0]
                base = parsed._replace(query="").geturl()
                test_url = f"{base}?{first_param}={payload}"
                r2 = requests.get(test_url, timeout=TIMEOUT)
                if payload in r2.text:
                    findings.append({"issue": "Reflected XSS (heuristic)", "details": test_url, "severity": "High", "recommendation": "Output-encode user-supplied content."})
        except Exception as e:
            findings.append({"issue": "XSS test failed", "details": str(e), "severity": "Low"})

        # directory traversal heuristic
        try:
            test_url = urljoin(url, "../" * 6 + "etc/passwd")
            r3 = requests.get(test_url, timeout=TIMEOUT, allow_redirects=True)
            if "root:" in r3.text and r3.status_code == 200:
                findings.append({"issue": "Directory traversal (very serious)", "details": test_url, "severity": "Critical", "recommendation": "Fix path sanitization and restrict file access."})
        except Exception:
            pass

    return {"findings": findings, "forms_count": len(forms)}

# -----------------------
# File/directory brute force (simple, respectful)
# -----------------------
def dir_bruteforce(base_url, wordlist=None, intrusive=False):
    if wordlist is None:
        wordlist = DEFAULT_WORDLIST
    results = []
    try:
        for w in wordlist:
            # be kind: sleep briefly to avoid hammering
            path = w if w.startswith("/") else f"/{w}"
            test_url = urljoin(base_url, path)
            try:
                r = requests.head(test_url, timeout=TIMEOUT, allow_redirects=True)
                code = r.status_code
                if code < 400:
                    results.append({"path": path, "status": code})
                # small delay
                time.sleep(0.1)
            except requests.RequestException:
                continue
    except Exception as e:
        return {"error": str(e)}
    return {"discovered": results}

# -----------------------
# Basic CVE lookup (uses NVD public API; may be rate limited)
# -----------------------
def cve_lookup(keyword, max_results=5):
    # Query NVD for a keyword; this is a best-effort lookup and may fail without API key.
    endpoint = "https://services.nvd.nist.gov/rest/json/cves/1.0"
    params = {"keyword": keyword, "resultsPerPage": max_results}
    try:
        r = requests.get(endpoint, params=params, timeout=10)
        data = r.json()
        items = data.get("result", {}).get("CVE_Items", [])
        out = []
        for it in items[:max_results]:
            meta = it.get("cve", {}).get("metadata", {})
            cid = it.get("cve", {}).get("CVE_data_meta", {}).get("ID", "")
            descs = it.get("cve", {}).get("description", {}).get("description_data", [])
            desc = descs[0]["value"] if descs else ""
            out.append({"id": cid, "description": desc})
        return {"cves": out}
    except Exception as e:
        return {"error": str(e)}

# -----------------------
# Orchestration & CLI
# -----------------------
def run_module_safe(name, func, *args, **kwargs):
    try:
        print_status(f"[*] Running module: {name}")
        start = time.time()
        res = func(*args, **kwargs)
        elapsed = time.time() - start
        print_ok(f"[+] Module {name} finished in {elapsed:.1f}s")
        return {"module": name, "status": "ok", "result": res}
    except Exception as e:
        print_err(f"[-] Module {name} failed: {e}")
        return {"module": name, "status": "error", "error": str(e)}

def save_results(target, results):
    ts = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    fname = f"scan_{target.replace(':','_')}_{ts}.json"
    with open(fname, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
    return fname

def main():
    print_status("Advanced Vulnerability Scanner Framework (educational use only)\n", Fore.CYAN)
    raw = input("Target (URL or IP[:port]): ").strip()
    if not raw:
        print_err("No target provided. Exiting.")
        sys.exit(1)
    try:
        target = normalize_target(raw)
    except Exception as e:
        print_err(f"Invalid target: {e}")
        sys.exit(1)

    print_status(f"Resolved target: {target['host']} on port {target['port']}")
    intrusive = input("Enable intrusive tests (will perform active payload checks)? (y/N): ").strip().lower() == "y"

    mode = input("Scan mode - (1) Full scan, (2) Select modules: ").strip()
    modules = []
    if mode == "2":
        print("Available modules:")
        print("1. Port scan")
        print("2. Service fingerprinting")
        print("3. Web vulnerabilities")
        print("4. SSL/TLS checks")
        print("5. Header analysis")
        print("6. Directory brute force")
        print("7. CVE lookup")
        picks = input("Enter comma-separated module numbers to run (e.g. 1,3,5): ")
        for p in picks.split(","):
            p = p.strip()
            if p == "1": modules.append("port")
            if p == "2": modules.append("fingerprint")
            if p == "3": modules.append("webvuln")
            if p == "4": modules.append("ssl")
            if p == "5": modules.append("headers")
            if p == "6": modules.append("dirbrute")
            if p == "7": modules.append("cve")
    else:
        modules = ["port", "fingerprint", "webvuln", "ssl", "headers", "dirbrute", "cve"]

    report = {
        "target": {"raw": raw, "host": target["host"], "port": target["port"], "url": target["url"]},
        "scan_time_utc": datetime.utcnow().isoformat() + "Z",
        "modules": {},
        "vulnerabilities": []
    }

    # Port scan
    port_results = {}
    if "port" in modules:
        r = run_module_safe("port_scan_socket", port_scan_socket, target["host"], DEFAULT_PORTS)
        report["modules"]["port_scan_socket"] = r
        if r.get("status")=="ok":
            port_results = r["result"]
        else:
            port_results = {}

    # Optional nmap (try to enrich)
    if "port" in modules:
        r2 = run_module_safe("port_scan_nmap", port_scan_nmap, target["host"])
        report["modules"]["port_scan_nmap"] = r2

    # Service fingerprinting
    if "fingerprint" in modules:
        r = run_module_safe("service_fingerprint", service_fingerprint, target, port_results)
        report["modules"]["service_fingerprint"] = r
        # add findings to vulnerabilities if something suspicious in banners
        if r.get("status")=="ok":
            sf = r["result"]
            for p, info in sf.items():
                if isinstance(p, int) and info.get("banner"):
                    b = info["banner"].lower()
                    if "apache" in b:
                        report["vulnerabilities"].append({"issue": "Apache server detected", "details": f"port {p} banner: {info['banner']}", "severity": "Low", "recommendation": "Keep server patched."})

    # Header analysis
    if "headers" in modules:
        r = run_module_safe("header_analysis", header_analysis, target["url"])
        report["modules"]["header_analysis"] = r
        if r.get("status")=="ok":
            ha = r["result"]
            if ha.get("missing"):
                for h in ha["missing"]:
                    report["vulnerabilities"].append({"issue": "Missing security header", "details": h, "severity": "Medium", "recommendation": f"Implement {h} header."})

    # SSL/TLS
    if "ssl" in modules:
        # choose port 443 or provided
        ssl_port = 443 if target["port"] not in (443, 8443) else target["port"]
        r = run_module_safe("ssl_scan", ssl_scan, target["host"], ssl_port)
        report["modules"]["ssl_scan"] = r
        if r.get("status")=="ok":
            sres = r["result"]
            if sres.get("expired"):
                report["vulnerabilities"].append({"issue": "Expired TLS certificate", "details": sres.get("notAfter"), "severity": "High", "recommendation": "Renew certificate immediately."})
            # old protocol support
            for proto, sup in sres.get("protocol_support", {}).items():
                if sup and proto in ("SSLv3","TLSv1"):
                    report["vulnerabilities"].append({"issue": "Weak TLS/SSL protocol supported", "details": proto, "severity": "High", "recommendation": "Disable old/insecure protocols (use TLS1.2+)."})
    # Web vulnerability checks
    if "webvuln" in modules:
        r = run_module_safe("basic_web_vuln_scan", basic_web_vuln_scan, target["url"], intrusive)
        report["modules"]["web_vuln_scan"] = r
        if r.get("status")=="ok":
            findings = r["result"].get("findings", [])
            for f in findings:
                report["vulnerabilities"].append(f)

    # Directory brute force
    if "dirbrute" in modules:
        r = run_module_safe("dir_bruteforce", dir_bruteforce, target["url"], None, intrusive)
        report["modules"]["dir_bruteforce"] = r
        if r.get("status")=="ok":
            discovered = r["result"].get("discovered", [])
            for d in discovered:
                report["vulnerabilities"].append({"issue": "Exposed resource", "details": d["path"], "severity": "Medium", "recommendation": "Remove or restrict access to sensitive files."})

    # CVE lookup - use detected service names (best-effort)
    if "cve" in modules:
        service_names = []
        sf_res = report["modules"].get("service_fingerprint", {})
        sreq = sf_res.get("result", {}) if sf_res.get("status")=="ok" else {}
        # gather some keywords
        if isinstance(sreq, dict):
            for k,v in sreq.items():
                if isinstance(v, dict):
                    banner = v.get("banner","")
                    if banner:
                        service_names += banner.split()
            http_server = sreq.get("http_server_header")
            if http_server:
                service_names += http_server.split()
        keywords = list(dict.fromkeys([s.strip().strip("/;,") for s in service_names if s]))
        cve_results = {}
        for kw in (keywords[:3] or [target["host"]]):
            r = run_module_safe(f"cve_lookup:{kw}", cve_lookup, kw)
            report["modules"].setdefault("cve_lookup", []).append(r)
            if r.get("status")=="ok":
                cve_results[kw] = r["result"]
        report["modules"]["cve_summary"] = cve_results

    # Summarize findings and assign severities if missing
    for v in report["vulnerabilities"]:
        if "severity" not in v:
            # simple heuristic placeholder
            v["severity"] = "Medium"

    # Build structured output
    structured = {
        "target_information": report["target"],
        "scan_time_utc": report["scan_time_utc"],
        "modules_run": list(report["modules"].keys()),
        "vulnerabilities_found": report["vulnerabilities"],
        "recommendations": [v.get("recommendation","") for v in report["vulnerabilities"] if v.get("recommendation")],
        "raw_modules": report["modules"]
    }

    fname = save_results(target["host"] + f"_{target['port']}", structured)
    print_ok(f"\nScan complete. Results saved to {fname}")
    # print concise summary
    print_status("\nSummary:")
    if structured["vulnerabilities_found"]:
        for v in structured["vulnerabilities_found"]:
            sev = v.get("severity","Unknown")
            color = Fore.RED if sev in ("Critical","High") else Fore.YELLOW if sev=="Medium" else Fore.CYAN
            print(color + f"- [{sev}] {v.get('issue')} -> {v.get('details')}" + Style.RESET_ALL)
    else:
        print_ok("No issues found by current checks.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print_err("\nScan interrupted by user.")

        sys.exit(1)

from . import __version__

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--version", action="version", version=f"vuln {__version__}")
    args = parser.parse_args()
    
