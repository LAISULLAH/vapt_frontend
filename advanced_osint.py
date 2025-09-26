#!/usr/bin/env python3
"""
advanced_osint.py
Advanced OSINT collector & AI-style summarizer for domain/IP.

Features:
- whois
- crt.sh subdomain enumeration (JSON)
- DNS records (dig or dnspython)
- TXT/SPF/DMARC checks
- Basic subdomain takeover heuristics (CNAME provider checks)
- HTTP header / title tech detection
- Optional Shodan integration if SHODAN_API set and shodan installed
- JSON + HTML report generation + small AI-style summary
"""

import os
import sys
import json
import subprocess
import socket
import re
from datetime import datetime
from urllib.parse import urlparse

# Optional imports (best-effort)
try:
    import requests
except Exception:
    requests = None

try:
    import dns.resolver
except Exception:
    dns = None

try:
    from jinja2 import Template
except Exception:
    Template = None

# Try shodan
SHODAN_API = os.environ.get("SHODAN_API")
try:
    if SHODAN_API:
        import shodan
    else:
        shodan = None
except Exception:
    shodan = None

REPORTS_DIR = "reports"
RAW_DIR = os.path.join(REPORTS_DIR, "raw")
os.makedirs(RAW_DIR, exist_ok=True)
os.makedirs(REPORTS_DIR, exist_ok=True)

# Timeouts
HTTP_TIMEOUT = 6.0
DNS_TIMEOUT = 5.0

# Common provider signs for takeover heuristics
TAKEOVER_SIGNALS = [
    "heroku", "github.io", "githubusercontent", "aws", "s3.amazonaws.com",
    "amazons3", "azurewebsites", "azureedge", "cloudfront", "netlify",
    "fastly", "digitaloceanspaces", "cdn", "googlehosted", "ghs.googlehosted",
    "ghs.google.com", "rackcdn", "wpengine"
]

# Utility: run subprocess and save output to file
def run_cmd_save(cmd, outpath, shell=False):
    try:
        with open(outpath, "w", encoding="utf-8") as f:
            proc = subprocess.run(cmd if isinstance(cmd, list) else cmd, stdout=f, stderr=subprocess.STDOUT, shell=shell, check=False, text=True, timeout=120)
        return True
    except Exception as e:
        with open(outpath, "w", encoding="utf-8") as f:
            f.write(f"ERROR running command: {cmd}\nException: {e}\n")
        return False

# Check if command exists
def has_cmd(name):
    return subprocess.call(["which", name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0

# WHOIS (use system whois if available)
def do_whois(target):
    out = ""
    outfile = os.path.join(RAW_DIR, f"{target}_whois.txt")
    if has_cmd("whois"):
        run_cmd_save(["whois", target], outfile)
        out = open(outfile, "r", encoding="utf-8", errors="ignore").read()
    else:
        out = f"[INFO] whois command not found on system. Please install whois.\n"
        with open(outfile, "w", encoding="utf-8") as f:
            f.write(out)
    return out, outfile

# crt.sh lookup (JSON)
def crtsh_lookup(domain):
    outfile = os.path.join(RAW_DIR, f"{domain}_crtsh.json")
    if not requests:
        msg = "[INFO] requests library not installed. Install 'requests' for crt.sh lookup."
        open(outfile, "w", encoding="utf-8").write(msg)
        return [], outfile
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        r = requests.get(url, timeout=10)
        if r.status_code != 200:
            open(outfile, "w", encoding="utf-8").write(f"crt.sh returned status {r.status_code}\n{r.text}")
            return [], outfile
        data = r.json()
        open(outfile, "w", encoding="utf-8").write(json.dumps(data, indent=2))
        # Extract unique names
        names = set()
        for item in data:
            nv = item.get("name_value")
            if nv:
                # name_value may be multiline; split
                for part in nv.splitlines():
                    names.add(part.strip().lower())
        subdomains = sorted(names)
        return subdomains, outfile
    except Exception as e:
        open(outfile, "w", encoding="utf-8").write(f"ERROR: {e}\n")
        return [], outfile

# DNS records: try dig -> fallback to dns.resolver -> fallback to socket
def dns_lookup(domain):
    outfile = os.path.join(RAW_DIR, f"{domain}_dns.txt")
    results = {"A": [], "AAAA": [], "MX": [], "NS": [], "TXT": [], "CNAME": []}
    if has_cmd("dig"):
        cmd = ["dig", domain, "ANY", "+noall", "+answer"]
        run_cmd_save(cmd, outfile)
        text = open(outfile, "r", encoding="utf-8", errors="ignore").read()
        # simple parse
        for line in text.splitlines():
            parts = re.split(r"\s+", line.strip())
            if len(parts) >= 5:
                rtype = parts[3].upper()
                rdata = " ".join(parts[4:])
                if rtype in results:
                    results[rtype].append(rdata)
                else:
                    # store unknown types in TXT
                    results["TXT"].append(f"{rtype}: {rdata}")
        return results, outfile
    elif dns:
        resolver = dns.resolver.Resolver()
        resolver.lifetime = DNS_TIMEOUT
        for rtype in ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]:
            try:
                answers = resolver.resolve(domain, rtype, lifetime=DNS_TIMEOUT)
                for r in answers:
                    results[rtype].append(str(r).strip())
            except Exception:
                pass
        open(outfile, "w", encoding="utf-8").write(json.dumps(results, indent=2))
        return results, outfile
    else:
        # fallback: resolve A using socket
        try:
            addr = socket.gethostbyname(domain)
            results["A"].append(addr)
        except Exception:
            pass
        open(outfile, "w", encoding="utf-8").write(json.dumps(results, indent=2))
        return results, outfile

# Get TXT records and check SPF/DMARC
def analyze_email_security(domain, dns_results):
    info = {"has_spf": False, "spf": [], "has_dmarc": False, "dmarc": None}
    # Check TXT entries
    for txt in dns_results.get("TXT", []):
        t = txt.lower()
        if "v=spf1" in t:
            info["has_spf"] = True
            info["spf"].append(txt)
    # DMARC is in _dmarc subdomain
    try:
        dname = f"_dmarc.{domain}"
        if has_cmd("dig"):
            cmd = ["dig", dname, "TXT", "+short"]
            out = subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL, timeout=8)
            if out.strip():
                info["has_dmarc"] = True
                info["dmarc"] = out.strip()
        elif dns:
            answers = dns.resolver.resolve(dname, "TXT", lifetime=DNS_TIMEOUT)
            for r in answers:
                info["has_dmarc"] = True
                info["dmarc"] = str(r)
    except Exception:
        pass
    return info

# Resolve a hostname to check CNAME and A
def resolve_host(host):
    res = {"host": host, "resolved": False, "ip": [], "cname": None}
    try:
        if has_cmd("dig"):
            out = subprocess.check_output(["dig", host, "CNAME", "+noall", "+answer"], text=True, stderr=subprocess.DEVNULL, timeout=6)
            if out.strip():
                # parse CNAME result line
                for line in out.splitlines():
                    parts = re.split(r"\s+", line.strip())
                    if len(parts) >= 5 and parts[3].upper() == "CNAME":
                        res["cname"] = parts[4]
            # A record
            out2 = subprocess.check_output(["dig", host, "A", "+short"], text=True, stderr=subprocess.DEVNULL, timeout=6)
            if out2.strip():
                res["ip"] = [l.strip() for l in out2.splitlines() if l.strip()]
                res["resolved"] = True
        elif dns:
            try:
                ans = dns.resolver.resolve(host, "A", lifetime=DNS_TIMEOUT)
                res["ip"] = [str(r) for r in ans]
                res["resolved"] = True
            except Exception:
                pass
            try:
                ans = dns.resolver.resolve(host, "CNAME", lifetime=DNS_TIMEOUT)
                for r in ans:
                    res["cname"] = str(r.target)
            except Exception:
                pass
        else:
            ip = socket.gethostbyname(host)
            res["ip"] = [ip]
            res["resolved"] = True
    except Exception:
        pass
    return res

# Basic HTTP tech detection: headers, server, title, common paths
def http_tech_detect(host):
    data = {"host": host, "reachable": False, "url": None, "status": None, "server": None, "title": None, "headers": {}}
    if not requests:
        return data
    # prefer https then http
    schemes = ["https://", "http://"]
    for scheme in schemes:
        url = scheme + host
        try:
            resp = requests.get(url, timeout=HTTP_TIMEOUT, verify=False)
            data["reachable"] = True
            data["url"] = url
            data["status"] = resp.status_code
            data["headers"] = dict(resp.headers)
            data["server"] = resp.headers.get("Server") or resp.headers.get("server")
            # extract title
            m = re.search(r"<title>(.*?)</title>", resp.text, re.IGNORECASE|re.DOTALL)
            if m:
                data["title"] = m.group(1).strip()
            break
        except Exception:
            continue
    return data

# Shodan info (optional)
def shodan_lookup(target):
    if not shodan or not SHODAN_API:
        return None
    try:
        api = shodan.Shodan(SHODAN_API)
        # If target is domain, try resolve to IP first
        try:
            ip = socket.gethostbyname(target)
        except Exception:
            ip = target
        info = api.host(ip)
        return info
    except Exception as e:
        return {"error": str(e)}

# Simple AI-style synthesizer for summary
def ai_summarize(report):
    lines = []
    lines.append(f"AI Summary for {report.get('target')}")
    lines.append(f"Generated: {report.get('generated')}\n")
    # Whois hints
    whois = report.get("whois_text","").lower()
    if "registrar" in whois or "registrant" in whois:
        lines.append("• Domain ownership information present.")
    # Expiry detection
    if re.search(r"\d{4}-\d{2}-\d{2}", whois):
        lines.append("• Domain has creation/expiry dates visible.")
    # Subdomains
    sdcount = len(report.get("subdomains",[]))
    lines.append(f"• Found {sdcount} potential subdomains via crt.sh.")
    # DNS/email risk
    em = report.get("email_security", {})
    if not em.get("has_spf"):
        lines.append("⚠️ SPF record missing — email spoofing risk.")
    else:
        lines.append("• SPF record present.")
    if not em.get("has_dmarc"):
        lines.append("⚠️ DMARC missing — consider adding to improve email security.")
    # Takeover risk
    takeovers = [s for s in report.get("subdomain_details",[]) if s.get("takeover_risk")]
    if takeovers:
        lines.append(f"⚠️ {len(takeovers)} subdomains show takeover indicators (CNAME -> third-party).")
    # HTTP issues
    http_issues = [h for h in report.get("http_hosts",[]) if h.get("server") is None or (h.get("status") and h.get("status")>=400)]
    if http_issues:
        lines.append(f"• {len(http_issues)} hosts returned error/unknown server headers.")
    # Shodan hint
    if report.get("shodan"):
        lines.append("• Shodan data available (see report) — exposed services may be visible.")
    # Overall risk estimate (very rough)
    risk_score = 0
    if not em.get("has_spf"): risk_score += 1
    if not em.get("has_dmarc"): risk_score += 1
    if len(takeovers)>0: risk_score += 2
    if sdcount>50: risk_score += 1
    if risk_score >=3:
        lines.append("\nOverall Risk: HIGH — actionable items found.")
    elif risk_score == 2:
        lines.append("\nOverall Risk: MEDIUM — some configuration issues.")
    else:
        lines.append("\nOverall Risk: LOW — no obvious critical issues found.")
    return "\n".join(lines)

# HTML template fallback (simple)
HTML_TEMPLATE = """
<!doctype html>
<html>
<head><meta charset="utf-8"><title>OSINT Report - {{target}}</title>
<style>body{font-family:Arial;padding:18px}h1{color:#1a73e8}table{width:100%;border-collapse:collapse}th,td{border:1px solid #ddd;padding:8px}th{background:#f4f6f8}</style>
</head>
<body>
<h1>OSINT Report — {{target}}</h1>
<p>Generated: {{generated}}</p>
<h2>AI Summary</h2><pre>{{ai_summary}}</pre>
<h2>Key Facts</h2>
<ul>
<li>Subdomains found: {{sub_count}}</li>
<li>SPF: {{spf}}</li>
<li>DMARC: {{dmarc}}</li>
</ul>
<h2>Subdomains (sample)</h2>
<ul>
{% for s in subdomains[:200] %}
  <li>{{s}}</li>
{% endfor %}
</ul>
<h2>Subdomain details (first 50)</h2>
<table>
<thead><tr><th>Subdomain</th><th>Resolved</th><th>IPs</th><th>CNAME</th><th>TakeoverRisk</th></tr></thead>
<tbody>
{% for d in subdetails[:50] %}
<tr><td>{{d.host}}</td><td>{{d.resolved}}</td><td>{{d.ip|join(', ')}}</td><td>{{d.cname}}</td><td>{{d.takeover_risk}}</td></tr>
{% endfor %}
</tbody></table>
<h2>HTTP host detections</h2>
<table><thead><tr><th>Host</th><th>URL</th><th>Status</th><th>Server</th><th>Title</th></tr></thead>
<tbody>
{% for h in http_hosts %}<tr><td>{{h.host}}</td><td>{{h.url}}</td><td>{{h.status}}</td><td>{{h.server}}</td><td>{{h.title}}</td></tr>{% endfor %}
</tbody></table>
</body></html>
"""

def make_report(target):
    t0 = datetime.utcnow().isoformat()
    target = target.strip()
    report = {"target": target, "generated": t0}

    # WHOIS
    whois_text, whois_file = do_whois(target)
    report["whois_text"] = whois_text
    report["whois_raw"] = whois_file

    # crt.sh
    subs, crt_file = crtsh_lookup(target)
    report["subdomains"] = subs
    report["crtsh_raw"] = crt_file

    # DNS
    dns_res, dns_file = dns_lookup(target)
    report["dns"] = dns_res
    report["dns_raw"] = dns_file

    # Email/SPF/DMARC
    report["email_security"] = analyze_email_security(target, dns_res)

    # Subdomain details (resolve + cname + takeover heuristic + http detect)
    subdetails = []
    http_hosts = []
    # include root host too
    hosts_to_check = []
    if target not in subs:
        hosts_to_check.append(target)
    # flatten subdomains: some entries in crt.sh include wildcards or multiple hostnames per line
    for s in subs:
        # crt.sh results can contain entries like "*.example.com" or "example.com\nwww.example.com"
        for part in s.split():
            part = part.strip().lstrip("*.").lower()
            if part and part not in hosts_to_check:
                hosts_to_check.append(part)

    # limit checks to avoid heavy runs; but we will check a reasonable amount (first 300)
    MAX_CHECK = 300
    hosts_to_check = hosts_to_check[:MAX_CHECK]

    for h in hosts_to_check:
        try:
            det = resolve_host(h)
            # takeover heuristic: check if cname contains known providers or if cname exists but no A
            take_risk = False
            cname = det.get("cname") or ""
            for sig in TAKEOVER_SIGNALS:
                if sig in (cname or "").lower():
                    take_risk = True
            if not det["resolved"] and cname:
                # unresolved cname -> potential takeover
                take_risk = True
            det["takeover_risk"] = take_risk
            subdetails.append(det)
            # HTTP check for hosts that resolved or seem web
            http = http_tech_detect(h)
            if http["reachable"] or det["resolved"]:
                http_hosts.append(http)
        except Exception:
            continue

    report["subdomain_details"] = subdetails
    report["http_hosts"] = http_hosts

    # Shodan (optional)
    if SHODAN_API and shodan:
        try:
            sdata = shodan_lookup(target)
            report["shodan"] = sdata
        except Exception as e:
            report["shodan_error"] = str(e)

    # AI summary
    report["ai_summary"] = ai_summarize(report)

    # Save JSON
    json_path = os.path.join(REPORTS_DIR, f"{target}_report.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    # Generate HTML if jinja2 available, else use basic template
    html_path = os.path.join(REPORTS_DIR, f"{target}_report.html")
    try:
        if Template:
            tpl = Template(HTML_TEMPLATE)
            html = tpl.render(target=target, generated=t0, ai_summary=report["ai_summary"],
                              sub_count=len(report["subdomains"]), spf=bool(report["email_security"].get("has_spf")),
                              dmarc=bool(report["email_security"].get("has_dmarc")),
                              subdomains=report["subdomains"], subdetails=report["subdomain_details"],
                              http_hosts=report["http_hosts"])
        else:
            html = HTML_TEMPLATE.replace("{{target}}", target).replace("{{generated}}", t0).replace("{{ai_summary}}", report["ai_summary"])
        with open(html_path, "w", encoding="utf-8") as f:
            f.write(html)
    except Exception as e:
        with open(html_path, "w", encoding="utf-8") as f:
            f.write(f"<pre>ERROR generating HTML: {e}</pre>\n<pre>{json.dumps(report, indent=2)}</pre>")

    print(f"[+] JSON report: {json_path}")
    print(f"[+] HTML report: {html_path}")
    print(f"[+] Raw files: {whois_file}, {crt_file}, {dns_file}")
    print("\n--- AI Summary ---\n")
    print(report["ai_summary"])
    return report

# CLI
def print_usage():
    print("Usage: python3 advanced_osint.py <domain_or_ip>")
    print("Optional: set SHODAN_API env var to include Shodan results (requires 'shodan' package).")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print_usage()
        sys.exit(1)
    target = sys.argv[1].strip()
    # Normalize input (remove http(s)://)
    if target.startswith("http://") or target.startswith("https://"):
        target = urlparse(target).hostname or target
    print(f"[+] Starting advanced OSINT for: {target}")
    make_report(target)

