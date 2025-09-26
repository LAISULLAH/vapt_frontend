#!/usr/bin/env python3
"""
recon_vapt.py
Hybrid OSINT + Recon + Vuln-scan (safe). Single-file tool.

Requirements (recommended):
    sudo apt install -y whois nmap nikto dnsutils curl
    pip install requests jinja2

Usage:
    python3 recon_vapt.py <target>
Example:
    python3 recon_vapt.py example.com
"""

import os, sys, json, re, subprocess, socket
from datetime import datetime, timezone

# Optional libs
try:
    import requests
except Exception:
    requests = None
try:
    from jinja2 import Template
except Exception:
    Template = None

# Config
REPORT_DIR = "reports"
RAW_DIR = os.path.join(REPORT_DIR, "raw")
os.makedirs(RAW_DIR, exist_ok=True)
os.makedirs(REPORT_DIR, exist_ok=True)

CMD_TIMEOUT = 25        # seconds for shell commands
HTTP_TIMEOUT = 6.0      # seconds for HTTP requests
MAX_SUB_CHECK = 200     # limit for active checks
BRUTE_WORDLIST = ["www","admin","test","dev","mail","ftp","blog","vpn","api","staging"]  # small optional list

TAKEOVER_SIGS = ["heroku", "github.io", "s3.amazonaws.com", "azurewebsites", "netlify", "cloudfront",
                 "fastly", "digitaloceanspaces", "gcp", "githubusercontent"]

def now_iso():
    return datetime.now(timezone.utc).isoformat()

def command_exists(cmd):
    return subprocess.call(["which", cmd], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0

def run_cmd(cmd, timeout=CMD_TIMEOUT, shell=False):
    """Run command, capture stdout/stderr, return (ok, text)."""
    try:
        if shell:
            proc = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=timeout)
        else:
            proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=timeout)
        return True, proc.stdout
    except subprocess.TimeoutExpired:
        return False, f"[!] TIMEOUT after {timeout}s for: {cmd}"
    except Exception as e:
        return False, f"[!] ERROR running {cmd}: {e}"

def save_raw(name, text):
    path = os.path.join(RAW_DIR, name)
    with open(path, "w", encoding="utf-8") as f:
        f.write(text or "")
    return path

# WHOIS
def whois_lookup(target):
    outname = f"{target}_whois.txt"
    if command_exists("whois"):
        ok, out = run_cmd(["whois", target])
    else:
        ok, out = False, "[!] whois missing on system"
    return save_raw(outname, out), out

# crt.sh subdomains
def crtsh_subdomains(domain):
    outname = f"{domain}_crtsh.json"
    if requests:
        try:
            url = f"https://crt.sh/?q=%25.{domain}&output=json"
            r = requests.get(url, timeout=10)
            txt = r.text
            save = save_raw(outname, txt)
            # parse unique hostnames
            try:
                j = r.json()
                names = set()
                for it in j:
                    nv = it.get("name_value","")
                    for part in nv.splitlines():
                        names.add(part.strip().lstrip("*.").lower())
                subs = sorted([n for n in names if n])
            except Exception:
                subs = []
            return save, subs, txt
        except Exception as e:
            return save_raw(outname, f"[!] crt.sh error: {e}"), [], f"[!] crt.sh error: {e}"
    else:
        if command_exists("curl"):
            ok, out = run_cmd(f"curl -s 'https://crt.sh/?q=%25.{domain}&output=json'", shell=True)
            save = save_raw(outname, out)
            names = re.findall(r'"name_value":"([^"]+)"', out)
            subsset = set()
            for nv in names:
                for p in nv.splitlines():
                    subsset.add(p.strip().lstrip("*.").lower())
            return save, sorted(subsset), out
        else:
            txt = "[!] requests/curl not available for crt.sh"
            return save_raw(outname, txt), [], txt

# DNS lookup (dig preferred)
def dns_lookup(domain):
    outname = f"{domain}_dns.txt"
    results = {"A": [], "AAAA": [], "MX": [], "NS": [], "TXT": [], "CNAME": []}
    if command_exists("dig"):
        ok, out = run_cmd(["dig", domain, "ANY", "+noall", "+answer"])
        save = save_raw(outname, out)
        for line in out.splitlines():
            parts = re.split(r"\s+", line.strip())
            if len(parts) >= 5:
                rtype = parts[3].upper()
                data = " ".join(parts[4:])
                if rtype in results:
                    results[rtype].append(data)
                else:
                    results["TXT"].append(f"{rtype}: {data}")
        return save, results, out
    else:
        # fallback quick A
        try:
            ip = socket.gethostbyname(domain)
            results["A"].append(ip)
            save = save_raw(outname, f"A: {ip}\n")
            return save, results, f"A: {ip}"
        except Exception as e:
            save = save_raw(outname, f"[!] DNS lookup failed: {e}")
            return save, results, f"[!] DNS lookup failed: {e}"

# Small brute (optional)
def brute_subdomains(domain, wordlist=BRUTE_WORDLIST):
    found = []
    for w in wordlist:
        host = f"{w}.{domain}"
        try:
            ip = socket.gethostbyname(host)
            found.append(host)
        except Exception:
            pass
    return sorted(set(found))

# Resolve host details
def resolve_host(host):
    entry = {"host": host, "resolved": False, "ips": [], "cname": None}
    if command_exists("dig"):
        ok, cname_out = run_cmd(["dig", host, "CNAME", "+noall", "+answer"])
        for line in cname_out.splitlines():
            p = re.split(r"\s+", line.strip())
            if len(p) >= 5 and p[3].upper() == "CNAME":
                entry["cname"] = p[4]
        ok2, a_out = run_cmd(["dig", host, "A", "+short"])
        ips = [l.strip() for l in a_out.splitlines() if l.strip()]
        if ips:
            entry["ips"] = ips
            entry["resolved"] = True
    else:
        try:
            ip = socket.gethostbyname(host)
            entry["ips"] = [ip]
            entry["resolved"] = True
        except Exception:
            pass
    return entry

# HTTP detect (headers, title)
def http_detect(host):
    info = {"host": host, "reachable": False, "url": None, "status": None, "server": None, "title": None}
    if requests:
        for scheme in ("https://", "http://"):
            try:
                url = scheme + host
                r = requests.get(url, timeout=HTTP_TIMEOUT, verify=False)
                info["reachable"] = True
                info["url"] = url
                info["status"] = r.status_code
                info["server"] = r.headers.get("Server")
                m = re.search(r"<title>(.*?)</title>", r.text, re.IGNORECASE|re.DOTALL)
                if m:
                    info["title"] = m.group(1).strip()
                break
            except Exception:
                continue
    else:
        if command_exists("curl"):
            ok, out = run_cmd(f"curl -Is --max-time {int(HTTP_TIMEOUT)} http://{host}", shell=True)
            info["reachable"] = "HTTP/" in out or "Server:" in out
            info["url"] = "http://" + host
            m = re.search(r"Server:\s*(.+)", out, re.IGNORECASE)
            if m: info["server"] = m.group(1).strip()
            m2 = re.search(r"<title>(.*?)</title>", out, re.IGNORECASE|re.DOTALL)
            if m2: info["title"] = m2.group(1).strip()
    return info

# Nmap quick
def nmap_quick(target):
    outname = f"{target}_nmap_quick.txt"
    if command_exists("nmap"):
        ok, out = run_cmd(["nmap", "--top-ports", "100", "-sV", target], timeout=120)
        path = save_raw(outname, out)
        return path, out
    else:
        return None, "[!] nmap missing"

# Nikto
def nikto_scan(url):
    outname = f"{url.replace('://','_').replace('/','_')}_nikto.txt"
    if command_exists("nikto"):
        ok, out = run_cmd(["nikto", "-host", url], timeout=180)
        path = save_raw(outname, out)
        return path, out
    else:
        return None, "[!] nikto missing"

# Check takeover heuristic
def takeover_check(cname):
    if not cname: return False
    low = cname.lower()
    for sig in TAKEOVER_SIGS:
        if sig in low: return True
    return False

# AI-style summary
def build_summary(report):
    lines = []
    lines.append(f"AI Summary for {report.get('target')} ({report.get('generated')})")
    # whois hint
    if report.get("whois_text"):
        lines.append("• WHOIS info present.")
    # email checks
    dns = report.get("dns",{})
    txts = dns.get("TXT",[])
    if not any("v=spf1" in t.lower() for t in txts):
        lines.append("⚠ No SPF record found")
    else:
        lines.append("• SPF present")
    # subdomains
    subcount = len(report.get("subdomains",[]))
    lines.append(f"• Subdomains discovered: {subcount}")
    # takeover
    tko = sum(1 for s in report.get("subdomain_details",[]) if s.get("takeover_risk"))
    if tko:
        lines.append(f"⚠ {tko} subdomains show takeover indicators")
    # nmap
    if report.get("nmap_raw") and "open" in report.get("nmap_raw","").lower():
        lines.append("• Nmap found open services — inspect quickly")
    # nikto
    if report.get("nikto_raw") and "OSVDB" in report.get("nikto_raw","") or "Server:" in (report.get("nikto_raw") or ""):
        lines.append("• Nikto output included (check vulnerabilities/warnings)")
    # overall
    risk = 0
    if not any("v=spf1" in t.lower() for t in txts): risk += 1
    if tko>0: risk += 2
    if subcount>50: risk +=1
    if risk>=3:
        lines.append("\nOverall Risk: HIGH")
    elif risk==2:
        lines.append("\nOverall Risk: MEDIUM")
    else:
        lines.append("\nOverall Risk: LOW")
    return "\n".join(lines)

# Build final report
def build_report(target):
    tgt = target.strip()
    print(f"[+] Starting scan for: {tgt}")
    gen = now_iso()
    report = {"target": tgt, "generated": gen}

    # WHOIS
    whois_path, whois_text = whois_lookup(tgt)
    report["whois_raw"] = whois_path
    report["whois_text"] = whois_text

    # CRT.SH
    crt_path, subs, crt_raw = crtsh_subdomains(tgt)
    report["crtsh_raw"] = crt_path
    report["subdomains"] = subs

    # small brute
    brute = brute_subdomains(tgt)
    for b in brute:
        if b not in report["subdomains"]:
            report["subdomains"].append(b)

    # DNS
    dns_path, dns_res, dns_raw = dns_lookup(tgt)
    report["dns_raw"] = dns_path
    report["dns"] = dns_res

    # nmap
    nmap_path, nmap_raw = nmap_quick(tgt)
    report["nmap_path"] = nmap_path
    report["nmap_raw"] = nmap_raw

    # nikto (if http present)
    http_url = f"http://{tgt}"
    nikto_path, nikto_raw = nikto_scan(http_url)
    report["nikto_path"] = nikto_path
    report["nikto_raw"] = nikto_raw

    # subdomain detail checks (resolve + cname + takeover + http detect)
    subdetails = []
    http_hosts = []
    hosts = [tgt]
    for s in report["subdomains"]:
        if s and s not in hosts:
            hosts.append(s)
    hosts = hosts[:MAX_SUB_CHECK]
    for h in hosts:
        det = resolve_host(h)
        det["takeover_risk"] = takeover_check(det.get("cname"))
        subdetails.append(det)
        http_hosts.append(http_detect(h))
    report["subdomain_details"] = subdetails
    report["http_hosts"] = http_hosts

    # summary
    report["ai_summary"] = build_summary(report)

    # save JSON
    jsonp = os.path.join(REPORT_DIR, f"{tgt}_report.json")
    with open(jsonp, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    # HTML (simple)
    htmlp = os.path.join(REPORT_DIR, f"{tgt}_report.html")
    try:
        if Template:
            tpl = Template("""
            <html><head><meta charset='utf-8'><title>Report - {{target}}</title></head><body>
            <h1>Report - {{target}}</h1><p>Generated: {{generated}}</p>
            <h2>AI Summary</h2><pre>{{ai_summary}}</pre>
            <h2>Subdomains ({{subcount}})</h2><pre>{{subs}}</pre>
            <h2>DNS</h2><pre>{{dns}}</pre>
            <h2>Nmap (excerpt)</h2><pre>{{nmap}}</pre>
            <h2>Nikto (excerpt)</h2><pre>{{nikto}}</pre>
            </body></html>
            """)
            html = tpl.render(target=tgt, generated=gen, ai_summary=report["ai_summary"],
                              subcount=len(report["subdomains"]), subs="\n".join(report["subdomains"][:500]),
                              dns=json.dumps(report["dns"], indent=2), nmap=report.get("nmap_raw",""),
                              nikto=report.get("nikto_raw",""))
        else:
            html = f"<html><body><h1>Report - {tgt}</h1><pre>{report['ai_summary']}</pre></body></html>"
        with open(htmlp, "w", encoding="utf-8") as f:
            f.write(html)
    except Exception as e:
        with open(htmlp, "w", encoding="utf-8") as f:
            f.write(f"ERROR generating HTML: {e}\n\n{report['ai_summary']}")

    print(f"[+] JSON -> {jsonp}")
    print(f"[+] HTML -> {htmlp}")
    print(f"[+] Raw -> {whois_path}, {crt_path}, {dns_path}")
    print("\n--- AI Summary ---\n")
    print(report["ai_summary"])
    print("\n[✓] Scan finished. Check reports/ folder.")

def usage():
    print("Usage: python3 recon_vapt.py <target>")
    print("Requires: whois, dig (dnsutils), curl (optional), nmap (optional), nikto (optional).")
    sys.exit(1)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        usage()
    target = sys.argv[1].strip()
    build_report(target)
