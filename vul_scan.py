#!/usr/bin/env python3
"""
vuln_scan_project.py
Single-file AI-like vulnerability scanner for academic project.
Features added (safe):
 - Nmap banner grabbing (multi-threaded)
 - Heuristic "AI-like" scoring & remediation suggestions
 - Passive HTTP header checks + TLS cert inspection
 - OSV (https://osv.dev) CVE lookup for product+version (informational only)
 - Exportable report (Markdown and JSON)
 - Lab simulation mode (--lab) to generate safe simulated findings for offline/VM testing
 - No exploit code, no active exploitation, only defensive guidance

Usage:
  python3 vuln_scan_project.py
  (Follow prompts; you'll be offered to export a report and/or enable lab simulation)
Dependencies:
  sudo apt install nmap
  pip3 install python-nmap requests colorama
"""

import nmap
import socket
import ssl
import re
import json
import time
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import Fore, Style, init
from datetime import datetime
import requests

# --------- init
init(autoreset=True)

# ===================== Banner =====================
def banner():
    print(Fore.RED + r"""
 ___    ___   _____ _____    _    __  __
/ _ \  |_ _| |_   _| ____|  / \  |  \/  |
| | | |  | |    | | |  _|   / _ \ | |\/| |
| |_| |  | |    | | | |___ / ___ \| |  | |
\___/  |___|   |_| |_____/_/   \_\_|  |_| 
==================================================
          AI TEAM - VULNERABILITY SCANNER
==================================================
""" + Style.RESET_ALL)

# ===================== Helpers =====================
def safe_resolve(target):
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        return None

def extract_version(s):
    if not s:
        return ""
    m = re.search(r'([\d]+\.[\d]+(\.[\d]+)?)', s)
    return m.group(1) if m else ""

def severity_from_score(score):
    if score >= 8:
        return "CRITICAL"
    if score >= 6:
        return "HIGH"
    if score >= 4:
        return "MEDIUM"
    return "LOW"

# ===================== OSV / CVE Lookup (informational only) =====================
def query_osv_ecosystem(package_name, package_version, timeout=8):
    """
    Query OSV API for advisories. Returns list of vulns (id, summary, references).
    This function is informational only — it does not exploit anything.
    """
    api = "https://api.osv.dev/v1/query"
    payload = {
        "version": package_version,
        "package": {
            "name": package_name
        }
    }
    headers = {"Content-Type": "application/json"}
    try:
        r = requests.post(api, json=payload, headers=headers, timeout=timeout)
        if r.status_code != 200:
            return {"ok": False, "error": f"OSV API {r.status_code}", "data": []}
        resp = r.json()
        vulns = []
        for item in resp.get("vulns", []):
            vid = item.get("id")
            summary = item.get("summary") or ""
            refs = [x.get("url") for x in item.get("references", []) if x.get("url")]
            # extract severity if available
            sev = None
            for severity_obj in item.get("severity", []):
                sev = severity_obj
            vulns.append({"id": vid, "summary": summary, "severity": sev, "references": refs})
        return {"ok": True, "data": vulns}
    except Exception as e:
        return {"ok": False, "error": str(e), "data": []}

def lookup_cves_for_service(name, product, version):
    """
    Heuristic wrapper: try product, name and some aliases to lookup OSV entries.
    Returns list of unique advisories.
    """
    candidates = []
    components = []
    if product:
        components.append(product.lower())
    if name and name.lower() not in components:
        components.append(name.lower())
    aliases = {
        "nginx": ["nginx"],
        "apache": ["apache", "apache httpd", "httpd"],
        "openssh": ["openssh", "ssh", "sshd"],
        "openssl": ["openssl"]
    }
    for comp in components:
        candidates.append(comp)
        if comp in aliases:
            candidates.extend(aliases[comp])

    results = []
    for cand in dict.fromkeys(candidates):
        if not cand:
            continue
        res = query_osv_ecosystem(cand, version)
        if res.get("ok") and res.get("data"):
            for v in res["data"]:
                v["_matched_as"] = cand
            results.extend(res["data"])
        time.sleep(0.2)
    # dedupe by id
    dedup = {}
    for v in results:
        dedup[v["id"]] = v
    return list(dedup.values())

# ===================== HTTP / TLS Passive Checks =====================
def check_http_headers(host, port=80, use_https=False, timeout=6):
    scheme = "https" if use_https else "http"
    url = f"{scheme}://{host}/"
    extra_notes = []
    try:
        resp = requests.get(url, timeout=timeout, allow_redirects=True, verify=False)
        headers = resp.headers
        body = resp.text[:8192].lower()
        # Directory listing heuristic
        if "index of /" in body or "<title>index of" in body:
            extra_notes.append("Possible directory listing at root (Index of / detected).")
        server = headers.get("Server", "")
        if server:
            extra_notes.append(f"Server header: {server}")
        # Security headers checks
        low_headers = {h.lower() for h in headers}
        if "strict-transport-security" not in low_headers:
            extra_notes.append("Missing Strict-Transport-Security header (HSTS).")
        if "x-frame-options" not in low_headers:
            extra_notes.append("Missing X-Frame-Options header.")
        if "x-content-type-options" not in low_headers:
            extra_notes.append("Missing X-Content-Type-Options header.")
        if "content-security-policy" not in low_headers:
            extra_notes.append("Missing Content-Security-Policy header (or not present).")
        return {"ok": True, "status_code": resp.status_code, "headers": dict(headers), "notes": extra_notes}
    except Exception as e:
        return {"ok": False, "error": str(e), "notes": extra_notes}

def check_tls_certificate(host, timeout=6):
    """Get peer cert and do light checks (expiry, SAN)."""
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, 443), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
        issues = []
        notAfter = cert.get('notAfter')
        san = cert.get('subjectAltName', ())
        try:
            # Common format: 'Oct 13 12:00:00 2025 GMT'
            exp_dt = datetime.strptime(notAfter, "%b %d %H:%M:%S %Y %Z")
            if exp_dt < datetime.utcnow():
                issues.append("Certificate expired.")
            else:
                days_left = (exp_dt - datetime.utcnow()).days
                if days_left < 30:
                    issues.append(f"Certificate expiring soon ({days_left} days).")
        except Exception:
            # ignore parse errors; we'll still return cert dict
            pass
        san_names = [name for (typ, name) in san if typ.lower() == 'dns']
        if san_names:
            if host not in san_names and not any(name.startswith("*.") and host.endswith(name[2:]) for name in san_names):
                issues.append("Certificate SAN does not include target hostname (possible mismatch).")
        else:
            issues.append("No SAN entries in certificate.")
        issuer = dict(x[0] for x in cert.get('issuer', ())) if cert.get('issuer') else {}
        return {"ok": True, "cert": cert, "issues": issues, "issuer": issuer}
    except Exception as e:
        return {"ok": False, "error": str(e)}

# ===================== Nmap port scan worker =====================
def scan_port(nm, ip, port):
    try:
        res = nm.scan(ip, str(port), arguments='-sV -Pn -T4 --version-intensity 2')
        scan_info = res.get('scan', {}).get(ip, {})
        tcp = scan_info.get('tcp', {})
        entry = tcp.get(port, {})
        state = entry.get('state', 'closed')
        name = entry.get('name', '') or entry.get('product', '') or ''
        product = entry.get('product', '') or ''
        version = entry.get('version', '') or extract_version(entry.get('extrainfo', '') or entry.get('version', ''))
        extra = entry.get('extrainfo', '') or ""
        return {"port": port, "state": state, "name": name, "product": product, "version": version, "extra": extra}
    except Exception as e:
        return {"port": port, "state": "error", "name": "error", "product": "", "version": "", "extra": str(e)}

# ===================== Prediction engine + mapping =====================
def predict_vulns(open_ports_info, http_checks=None, tls_check=None, do_cve_lookup=False, cve_cache=None):
    preds = []
    for info in open_ports_info:
        port = info['port']
        name = info.get('name') or ''
        product = info.get('product') or ''
        version = info.get('version') or ''
        extra = info.get('extra') or ''
        score = 0
        issues = []
        details = []
        remediation = []

        svc_label = f"{name} {product} {version}".strip()

        # Basic heuristics
        if port == 23:
            score += 5; issues.append("Telnet running (cleartext)."); remediation.append("Disable Telnet; use SSH.")
        if port == 21:
            score += 3; issues.append("FTP may allow anonymous/weak logins."); remediation.append("Disable anonymous FTP; use SFTP.")
        if port == 22:
            score += 2; issues.append("SSH exposed — check for password auth."); remediation.append("Use key-based auth, rate limiting.")
        if port in (80, 8080, 8000):
            score += 2; issues.append("HTTP service exposed."); remediation.append("Harden web server, validate inputs, use WAF.")
        if port == 443:
            score += 1; issues.append("HTTPS service exposed."); remediation.append("Ensure TLS config and patching.")
        if port in (139, 445):
            score += 4; issues.append("SMB exposed — high risk when internet accessible."); remediation.append("Block SMB on internet-facing interfaces.")
        if port in (3306, 5432, 1433):
            score += 3; issues.append("Database port open to network."); remediation.append("Do not expose DB publicly; restrict access.")

        # Banner/version rules
        if version:
            try:
                major = int(version.split('.')[0])
                if major < 1:
                    score += 2
                    details.append(f"Legacy version detected: {version}")
            except:
                pass
        if any(k in (product + " " + name + " " + extra).lower() for k in ["openssl 0.", "openssl 1.0", "openssl 1.1.0"]):
            score += 3
            details.append("Old OpenSSL family detected — risk of known TLS issues.")

        # Integrate passive http checks
        if http_checks and port in (80, 8080, 8000, 443):
            # prefer secure check if https root present
            hc = http_checks.get('root_https') if port == 443 and 'root_https' in http_checks else http_checks.get('root', {})
            if hc:
                if hc.get('ok'):
                    for note in hc.get('notes', []):
                        if "Missing" in note:
                            score += 1
                            details.append(note)
                        if "Possible directory listing" in note:
                            score += 2
                            issues.append("Directory listing detected at root.")
                            remediation.append("Disable directory listing; remove sensitive files.")
                        if note.startswith("Server header"):
                            details.append(note)
                else:
                    details.append("HTTP check failed: " + hc.get('error', 'unknown'))

        # TLS checks influence
        if tls_check and port == 443:
            if tls_check.get('ok'):
                for iss in tls_check.get('issues', []):
                    details.append("TLS: " + iss)
                    if "expired" in iss.lower():
                        score += 4
                        issues.append("TLS certificate expired or invalid.")
                        remediation.append("Renew certificate and ensure proper SAN.")
                    elif "mismatch" in iss.lower() or "no san" in iss.lower():
                        score += 2
                        remediation.append("Correct certificate SAN or reissue certificate.")
                    elif "expiring soon" in iss.lower():
                        score += 1
                        remediation.append("Plan certificate renewal.")
            else:
                details.append("TLS check failed: " + tls_check.get('error', 'unknown'))
                score += 1

        # Unknown service penalty
        if not name or name.lower() == 'unknown':
            score += 1
            details.append("Service could not be identified reliably via banner.")

        # Optional CVE lookup (informational only)
        cves = []
        if do_cve_lookup and (product or name) and version:
            key = f"{name}|{product}|{version}"
            if cve_cache is not None and key in cve_cache:
                cves = cve_cache[key]
            else:
                try:
                    cves = lookup_cves_for_service(name, product, version)
                    if cve_cache is not None:
                        cve_cache[key] = cves
                except Exception as e:
                    details.append(f"CVE lookup failed: {str(e)}")

        severity = severity_from_score(score)
        issue_text = issues[0] if issues else "Service exposure and configuration checks recommended."
        full_details = "; ".join(details + ([f"Banner extra: {extra}"] if extra else []))
        rem_text = " ".join(dict.fromkeys(remediation)) if remediation else "Review service config and access controls."

        preds.append({
            "port": port,
            "service": svc_label,
            "severity": severity,
            "score": score,
            "issue": issue_text,
            "details": full_details,
            "remediation": rem_text,
            "cves": cves
        })

    preds.sort(key=lambda x: x['score'], reverse=True)
    return preds

# ===================== Reporting helpers =====================
def export_report_md(target, ip, scan_info, predictions, filename):
    lines = []
    lines.append(f"# Vulnerability Scan Report")
    lines.append(f"- Target: {target} ({ip})")
    lines.append(f"- Time: {datetime.now().isoformat()}")
    lines.append("")
    lines.append("## Open Ports")
    for info in scan_info:
        lines.append(f"- Port {info['port']}: {info.get('name','')} {info.get('product','')} {info.get('version','')}")
    lines.append("")
    lines.append("## Findings")
    for p in predictions:
        lines.append(f"### Port {p['port']} — {p['service']}")
        lines.append(f"- Severity: {p['severity']} (score {p['score']}/10)")
        lines.append(f"- Issue: {p['issue']}")
        if p['details']:
            lines.append(f"- Details: {p['details']}")
        lines.append(f"- Remediation: {p['remediation']}")
        if p.get('cves'):
            lines.append(f"- Related advisories:")
            for c in p['cves'][:6]:
                lines.append(f"  - {c.get('id')} — {c.get('summary')[:200]}")
                for r in (c.get('references') or [])[:2]:
                    lines.append(f"    - {r}")
        lines.append("")
    content = "\n".join(lines)
    with open(filename, "w", encoding="utf-8") as f:
        f.write(content)
    return filename

def export_report_json(data, filename):
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, default=str)
    return filename

# ===================== Lab simulation (safe) =====================
def lab_simulation(open_ports_info):
    """
    Produce simulated 'vulnerable' findings for offline lab VMs.
    These are NOT real exploit actions — only fake findings to practice report/export.
    """
    simulated = []
    for info in open_ports_info:
        # make a gentle simulated increase in score for demonstration only
        s = {
            "port": info['port'],
            "service": f"{info.get('name','')} {info.get('product','')} {info.get('version','')}".strip(),
            "severity": "HIGH",
            "score": 7,
            "issue": "SIMULATED: Confirmed vulnerable in isolated lab (demo only).",
            "details": "This is simulated data for lab use only. No exploit was executed.",
            "remediation": "Patch the service in lab and test mitigation."
        }
        simulated.append(s)
    return simulated

# ===================== Main flow =====================
def vuln_scan(args):
    banner()
    target = input(Fore.YELLOW + "Enter target domain/IP: " + Style.RESET_ALL).strip()
    if not target:
        print(Fore.RED + "[!] No target entered." + Style.RESET_ALL)
        return

    ip = safe_resolve(target)
    if not ip:
        print(Fore.RED + "[!] Invalid host or DNS resolution failed." + Style.RESET_ALL)
        return

    print(Fore.CYAN + f"\n[+] Starting AI-like vulnerability scan for {target} ({ip}) at {datetime.now().isoformat()}...\n" + Style.RESET_ALL)

    full_scan = input("Scan full TCP range 1-65535? (y/n, default n): ").strip().lower()
    ports = range(1, 65536) if full_scan == 'y' else range(1, 1025)

    nm = nmap.PortScanner()
    open_ports_info = []

    print(Fore.CYAN + f"[+] Scanning {ip} ports: {ports.start}-{ports.stop - 1}...\n" + Style.RESET_ALL)

    max_workers = 30 if full_scan == 'y' else 20
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(scan_port, nm, ip, port): port for port in ports}
        for future in as_completed(futures):
            info = future.result()
            port = info['port']
            state = info.get('state', '')
            if state == 'open':
                name = info.get('name') or ''
                product = info.get('product') or ''
                version = info.get('version') or ''
                print(Fore.GREEN + f"[+] Open port found: {port} ({name} {product} {version})" + Style.RESET_ALL)
                open_ports_info.append(info)

    # Passive HTTP/TLS checks (only if relevant ports open)
    http_checks = {}
    if any(p['port'] in (80, 8080, 8000) for p in open_ports_info):
        http_checks['root'] = check_http_headers(target, port=80, use_https=False)
    if any(p['port'] == 443 for p in open_ports_info):
        http_checks['root_https'] = check_http_headers(target, port=443, use_https=True)
        tls_check = check_tls_certificate(target)
    else:
        tls_check = None

    # Ask whether to perform CVE lookups (informational only)
    do_cves = input("Lookup CVE advisories (OSV) for detected services? (y/n, default n): ").strip().lower() == 'y'
    cve_cache = {} if do_cves else None

    # If lab mode flag set, generate simulated results instead of live lookups
    if args.lab:
        print(Fore.MAGENTA + "[*] Lab simulation mode enabled — generating safe simulated findings (no network exploit performed)." + Style.RESET_ALL)
        simulated_preds = lab_simulation(open_ports_info)
        predictions = simulated_preds
    else:
        predictions = predict_vulns(open_ports_info, http_checks=http_checks, tls_check=tls_check, do_cve_lookup=do_cves, cve_cache=cve_cache)

    # Display predictions
    if predictions:
        print(Fore.CYAN + "\n[+] Predicted vulnerabilities and recommendations:\n" + Style.RESET_ALL)
        for p in predictions:
            sev_color = {
                "CRITICAL": Fore.RED + Style.BRIGHT,
                "HIGH": Fore.RED,
                "MEDIUM": Fore.YELLOW,
                "LOW": Fore.GREEN
            }.get(p['severity'], Fore.WHITE)
            print(sev_color + f"[{p['severity']}] Port {p['port']} - {p['service']}" + Style.RESET_ALL)
            print(Fore.MAGENTA + f"  Issue: {p['issue']}" + Style.RESET_ALL)
            if p.get('details'):
                print(Fore.CYAN + f"  Details: {p.get('details')}" + Style.RESET_ALL)
            if p.get('cves'):
                print(Fore.WHITE + f"  Related advisories (informational):" + Style.RESET_ALL)
                for c in p['cves'][:5]:
                    print(Fore.WHITE + f"   - {c.get('id')}: {c.get('summary')[:200]}" + Style.RESET_ALL)
            print(Fore.WHITE + f"  Risk score: {p['score']}/10" + Style.RESET_ALL)
            print(Fore.WHITE + f"  Remediation: {p['remediation']}\n" + Style.RESET_ALL)
    else:
        print(Fore.RED + "\n[!] No open ports detected." + Style.RESET_ALL)

    # Export option
    do_export = input("Export report? (y/n, default n): ").strip().lower() == 'y'
    if do_export:
        base = f"scan_{target.replace(':','_')}_{datetime.now().strftime('%Y%m%dT%H%M%S')}"
        mdfile = base + ".md"
        jsonfile = base + ".json"
        # prepare data
        report_data = {
            "target": target,
            "ip": ip,
            "time": datetime.now().isoformat(),
            "open_ports": open_ports_info,
            "predictions": predictions,
            "http_checks": http_checks,
            "tls_check": tls_check
        }
        export_report_md(target, ip, open_ports_info, predictions, mdfile)
        export_report_json(report_data, jsonfile)
        print(Fore.CYAN + f"[+] Reports written: {mdfile}, {jsonfile}" + Style.RESET_ALL)

    print(Fore.CYAN + "Scan finished. This tool provides assessment & suggestions only — do not use for unauthorized scanning." + Style.RESET_ALL)
    input(Fore.YELLOW + "\nPress Enter to finish..." + Style.RESET_ALL)

# ===================== CLI args =====================
def main():
    parser = argparse.ArgumentParser(description="AI-like vulnerability scanner (project-safe version).")
    parser.add_argument("--lab", action="store_true", help="Enable lab simulation mode (safe simulated findings).")
    args = parser.parse_args()
    vuln_scan(args)

if __name__ == "__main__":
    main()
