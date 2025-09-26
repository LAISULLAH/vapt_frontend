#!/usr/bin/env python3
"""
osint_logger.py

- Streams output for each step (WHOIS, crt.sh, dig fallback, HTTP, SSL, nmap, nikto)
- Writes a plain-text log (ANSI sequences removed) to reports/<domain>_live.log
- Also writes final full report to reports/<domain>.txt and opens with less -R
- Handles Ctrl+C and tries to restore terminal state
"""
import os, sys, subprocess, socket, ssl, shutil, io, re, signal, time, json
from datetime import datetime, timezone

import requests, urllib3
from colorama import init, Fore, Style

init(autoreset=True)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

REPORT_DIR = "reports"
os.makedirs(REPORT_DIR, exist_ok=True)

ANSI_RE = re.compile(r'\x1b\[[0-9;]*[A-Za-z]')  # simple ANSI escape stripper

def now(): return datetime.now(timezone.utc).isoformat()

def strip_ansi(s):
    return ANSI_RE.sub('', s)

def safe_print(s="", end="\n"):
    sys.stdout.write(s + end)
    sys.stdout.flush()

def write_log(logf, text):
    # write plain text (no ANSI) for easier scrolling later
    logf.write(strip_ansi(text))
    if not text.endswith("\n"):
        logf.write("\n")
    logf.flush()

def run_quick(cmd, timeout=30, logf=None):
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        out = proc.stdout or ""
        err = proc.stderr or ""
        combined = out + (("\n[stderr]\n" + err) if err else "")
        safe_print(combined)
        if logf:
            write_log(logf, combined)
        return proc.returncode, combined
    except subprocess.TimeoutExpired:
        msg = f"[ERROR] Command timed out after {timeout}s: {' '.join(cmd)}"
        safe_print(Fore.RED + msg)
        if logf: write_log(logf, msg)
        return 1, msg
    except Exception as e:
        msg = f"[ERROR] Exception running {' '.join(cmd)}: {e}"
        safe_print(Fore.RED + msg)
        if logf: write_log(logf, msg)
        return 1, msg

def run_stream_cmd(cmd, timeout=None, logf=None):
    # merge stdout/stderr and stream line-by-line
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1, universal_newlines=True)
    except FileNotFoundError:
        msg = f"[ERROR] Command not found: {cmd[0]}"
        safe_print(Fore.RED + msg)
        if logf: write_log(logf, msg)
        return 127, msg
    except Exception as e:
        msg = f"[ERROR] Could not start {cmd[0]}: {e}"
        safe_print(Fore.RED + msg)
        if logf: write_log(logf, msg)
        return 1, msg

    captured = io.StringIO()
    start = time.time()
    try:
        for line in proc.stdout:
            if line is None:
                break
            safe_print(line.rstrip())
            if logf: write_log(logf, line)
            captured.write(line)
            if timeout and (time.time()-start) > timeout:
                proc.kill()
                exmsg = f"[ERROR] Process killed after timeout {timeout}s"
                safe_print(Fore.RED + exmsg)
                if logf: write_log(logf, exmsg)
                return 1, captured.getvalue() + "\n" + exmsg
        ret = proc.wait(timeout=5)
        return ret, captured.getvalue()
    except Exception as e:
        try:
            proc.kill()
        except:
            pass
        msg = f"[ERROR] Exception while streaming {cmd[0]}: {e}"
        safe_print(Fore.RED + msg)
        if logf: write_log(logf, msg)
        return 1, captured.getvalue() + "\n" + msg

# Individual steps (sequential)
def whois_step(domain, logf):
    safe_print(Fore.MAGENTA + "\n[*] WHOIS Lookup\n" + "-"*60 + Style.RESET_ALL)
    if not shutil.which("whois"):
        msg = "whois binary not found. Install: sudo apt install whois"
        safe_print(Fore.YELLOW + "[-] " + msg)
        write_log(logf, msg)
        return msg
    rc, out = run_quick(["whois", domain], timeout=60, logf=logf)
    return out

def crtsh_step(domain, logf):
    safe_print(Fore.MAGENTA + "\n[*] Subdomains from crt.sh\n" + "-"*60 + Style.RESET_ALL)
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    headers = {"User-Agent":"Mozilla/5.0 (osint/1.0)"}
    try:
        r = requests.get(url, timeout=20, headers=headers)
        if r.status_code != 200:
            msg = f"crt.sh returned status {r.status_code}"
            safe_print(Fore.YELLOW + "[-] " + msg)
            write_log(logf, msg)
            return msg
        try:
            data = r.json()
            subs = sorted({e.get("name_value","") for e in data if e.get("name_value")})
            if not subs:
                safe_print(Fore.YELLOW + "[-] crt.sh returned no subdomains")
                write_log(logf, "(crt.sh empty)")
                return "(crt.sh empty)"
            for s in subs:
                safe_print(Fore.GREEN + "[+] " + s)
                write_log(logf, s)
            return "\n".join(subs)
        except ValueError:
            msg = "crt.sh returned non-JSON (maybe rate-limited)"
            safe_print(Fore.YELLOW + "[-] " + msg)
            write_log(logf, msg)
            return msg
    except Exception as e:
        msg = f"crt.sh request error: {e}"
        safe_print(Fore.RED + "[-] " + msg)
        write_log(logf, msg)
        return msg

def dns_step(domain, logf):
    safe_print(Fore.MAGENTA + "\n[*] DNS Lookup\n" + "-"*60 + Style.RESET_ALL)
    if shutil.which("dig"):
        rc, out = run_quick(["dig", domain, "ANY", "+short"], timeout=20, logf=logf)
        if rc == 0 and out.strip():
            return out.strip()
        else:
            safe_print(Fore.YELLOW + "[-] dig returned empty or error; falling back to socket")
            write_log(logf, "dig fallback")
    try:
        addrs = socket.getaddrinfo(domain, None)
        uniq = sorted({a[4][0] for a in addrs if a and a[4]})
        if uniq:
            for ip in uniq:
                safe_print(Fore.GREEN + "[+] " + ip)
                write_log(logf, ip)
            return "\n".join(uniq)
        else:
            msg = "No A/AAAA records found (socket fallback)"
            safe_print(Fore.YELLOW + "[-] " + msg)
            write_log(logf, msg)
            return msg
    except Exception as e:
        msg = f"DNS lookup failed: {e}"
        safe_print(Fore.RED + "[-] " + msg)
        write_log(logf, msg)
        return msg

def http_step(domain, logf):
    safe_print(Fore.MAGENTA + "\n[*] HTTP Headers\n" + "-"*60 + Style.RESET_ALL)
    for scheme in ("https://", "http://"):
        url = scheme + domain
        try:
            safe_print(Fore.CYAN + f"Trying {url}")
            r = requests.get(url, timeout=12, verify=False, headers={"User-Agent":"osint/1.0"})
            safe_print(Fore.GREEN + f"Status: {r.status_code}")
            for k,v in r.headers.items():
                safe_print(Fore.GREEN + f" {k}: {v}")
                write_log(logf, f"{url} {k}: {v}")
            return f"{url} -> {r.status_code}\n" + "\n".join(f"{k}: {v}" for k,v in r.headers.items())
        except Exception as e:
            safe_print(Fore.YELLOW + f"[-] {scheme} failed: {e}")
            write_log(logf, f"{scheme} failed: {e}")
    return "HTTP fetch failed for both https and http."

def ssl_step(domain, logf):
    safe_print(Fore.MAGENTA + "\n[*] SSL Certificate Info\n" + "-"*60 + Style.RESET_ALL)
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(10)
            s.connect((domain, 443))
            cert = s.getpeercert()
            text = json.dumps(cert, indent=2, default=str)
            safe_print(Fore.GREEN + text)
            write_log(logf, text)
            return text
    except Exception as e:
        msg = f"Failed to fetch SSL info: {e}"
        safe_print(Fore.RED + "[-] " + msg)
        write_log(logf, msg)
        return msg

def nmap_step(domain, logf):
    safe_print(Fore.MAGENTA + "\n[*] Nmap Scan (streaming)\n" + "-"*60 + Style.RESET_ALL)
    if not shutil.which("nmap"):
        msg = "nmap not installed"
        safe_print(Fore.RED + "[-] " + msg)
        write_log(logf, msg)
        return msg
    safe_print(Fore.CYAN + f"Running: nmap -sV -Pn {domain}")
    rc, captured = run_stream_cmd(["nmap", "-sV", "-Pn", domain], timeout=300, logf=logf)
    if rc == 0:
        safe_print(Fore.GREEN + "[✔] nmap finished")
    else:
        safe_print(Fore.YELLOW + f"[!] nmap ended with rc={rc}")
    return captured

def nikto_step(domain, logf):
    safe_print(Fore.MAGENTA + "\n[*] Nikto Scan (streaming)\n" + "-"*60 + Style.RESET_ALL)
    if not shutil.which("nikto"):
        msg = "nikto not installed"
        safe_print(Fore.RED + "[-] " + msg)
        write_log(logf, msg)
        return msg
    target = domain if domain.startswith("http") else f"http://{domain}"
    safe_print(Fore.CYAN + f"Running: nikto -h {target}")
    rc, captured = run_stream_cmd(["nikto", "-h", target], timeout=600, logf=logf)
    if rc == 0:
        safe_print(Fore.GREEN + "[✔] nikto finished")
    else:
        safe_print(Fore.YELLOW + f"[!] nikto ended with rc={rc}")
    return captured

def build_report_file(domain, live_log_path, aggregated):
    outpath = os.path.join(REPORT_DIR, f"{domain.replace('.', '_')}.txt")
    with open(outpath, "w") as f:
        f.write(f"Generated: {now()}\nTarget: {domain}\n" + "="*70 + "\n\n")
        for header, body in aggregated:
            f.write(f"--- {header} ---\n")
            if isinstance(body, list):
                f.write("\n".join(body) + "\n\n")
            else:
                f.write(str(body) + "\n\n")
        f.write("\n\n[Live log saved here: " + live_log_path + "]\n")
    return outpath

def handle_sigint(signum, frame):
    # try to restore terminal to sane state
    safe_print("\n[!] Interrupted by user (Ctrl+C). Restoring terminal state...")
    try:
        os.system("stty sane")
    except:
        pass
    sys.exit(1)

signal.signal(signal.SIGINT, handle_sigint)

def main():
    if len(sys.argv) >= 2:
        domain = sys.argv[1].strip()
    else:
        domain = input("Enter domain for OSINT scan: ").strip()
    if not domain:
        print("No domain provided. Exiting.")
        sys.exit(1)

    live_log_path = os.path.join(REPORT_DIR, f"{domain.replace('.', '_')}_live.log")
    with open(live_log_path, "w", encoding="utf-8") as logf:
        write_log(logf, f"Live run started: {now()} for {domain}")

        aggregated = []
        # WHOIS
        whois_out = whois_step(domain, logf)
        aggregated.append(("WHOIS", whois_out))

        # crt.sh
        crt_out = crtsh_step(domain, logf)
        aggregated.append(("Subdomains (crt.sh)", crt_out))

        # DNS
        dns_out = dns_step(domain, logf)
        aggregated.append(("DNS Records", dns_out))

        # HTTP
        http_out = http_step(domain, logf)
        aggregated.append(("HTTP Headers", http_out))

        # SSL
        ssl_out = ssl_step(domain, logf)
        aggregated.append(("SSL Certificate Info", ssl_out))

        # Nmap
        nmap_out = nmap_step(domain, logf)
        aggregated.append(("Nmap Scan", nmap_out))

        # Nikto
        nikto_out = nikto_step(domain, logf)
        aggregated.append(("Nikto Scan", nikto_out))

    report_file = build_report_file(domain, live_log_path, aggregated)
    safe_print(Fore.LIGHTCYAN_EX + f"\n[✔] Full report saved to: {report_file}" + Style.RESET_ALL)
    safe_print(Fore.LIGHTCYAN_EX + f"[✔] Plain live log saved to: {live_log_path}" + Style.RESET_ALL)

    # Try to open in less -R (if available) so colors preserved; fallback to plain less
    pager = shutil.which("less") or shutil.which("more")
    if pager:
        safe_print(f"\nOpening report with pager ({pager}). Use q to quit, PgUp/PgDn to scroll.")
        try:
            os.execv(pager, [pager, "-R", report_file])
        except Exception:
            try:
                os.execv(pager, [pager, report_file])
            except Exception:
                safe_print("Could not launch pager. Open the file manually:", report_file)
    else:
        safe_print("No pager found. Open the report manually:", report_file)

if __name__ == "__main__":
    main()
