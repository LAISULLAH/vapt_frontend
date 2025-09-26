#!/usr/bin/env python3
"""
subenum_cli.py
AI-powered subdomain enumerator with CLI support and big-wordlist (.txt) loading.

Usage examples:
    # interactive (asks domain etc.)
    python subenum_cli.py

    # CLI with external wordlist
    python subenum_cli.py -d example.com -w big_wordlist.txt -t 100 --timeout 4 --verify

    # Use default big_wordlist.txt in cwd (if present)
    python subenum_cli.py -d example.com --use-default

    # Quick single-run, write to custom report file
    python subenum_cli.py -d example.com -w subs.txt -o reports/my_report.txt
"""
import argparse
import requests
from colorama import Fore, Style, init
from concurrent.futures import ThreadPoolExecutor, as_completed
import os
import socket
import re
import time
import random
import string
import urllib3
from threading import Lock
from urllib.parse import urlparse

# Silence insecure request warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

init(autoreset=True)
lock = Lock()

# ---------------- banner ----------------
def banner():
    print(Fore.RED + r"""
    _    ___   _____ _____    _    __  __ 
   / \  |_ | |   _| ____|  / \  |  \/  |
  / _ \  | |    | | |  _|   / _ \ | |\/| |
 / ___ \ | |    | | | |___ / ___ \| |  | |
/_/   \_\___|   |_| |_____/_/   \_\_|  |_|

==================================================
     AI-Powered VAPT Toolkit - Subdomain Enum
==================================================
""" + Style.RESET_ALL)

# ---------------- defaults ----------------
BUILTIN_WORDLIST = [
    "www","mail","ftp","api","dev","test","staging","beta","admin","portal",
    "dashboard","login","secure","crm","shop","blog","forum","news","old","vpn",
    "support","webmail","docs","static","cdn","images","files","video","app"
]
DEFAULT_WORDLIST_PATH = "big_wordlist.txt"

# ---------------- utils ----------------
def read_external_wordlist(path):
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            lines = [l.strip() for l in f if l.strip() and not l.startswith("#")]
        return lines
    except Exception as e:
        print(Fore.RED + f"[!] Could not read external wordlist '{path}': {e}" + Style.RESET_ALL)
        return []

def load_default_wordlist():
    if os.path.exists(DEFAULT_WORDLIST_PATH):
        print(Fore.CYAN + f"[+] Loaded default big wordlist from {DEFAULT_WORDLIST_PATH}" + Style.RESET_ALL)
        return read_external_wordlist(DEFAULT_WORDLIST_PATH)
    else:
        print(Fore.YELLOW + "[!] No big_wordlist.txt found, using builtin small list." + Style.RESET_ALL)
        return BUILTIN_WORDLIST.copy()

def random_label(length=12):
    return ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(length))

def extract_title(html_text):
    if not html_text:
        return ""
    m = re.search(r"<title[^>]*>(.*?)</title>", html_text, re.IGNORECASE | re.DOTALL)
    if m:
        return re.sub(r"\s+", " ", m.group(1)).strip()
    return ""

def normalize_url(url):
    try:
        p = urlparse(url)
        host = p.netloc.lower().rstrip('/')
        scheme = p.scheme.lower()
        return host, scheme, url.rstrip('/')
    except Exception:
        return url, "http", url

# ---------------- network check ----------------
def dns_resolves(name):
    try:
        socket.getaddrinfo(name, None)
        return True
    except socket.gaierror:
        return False
    except Exception:
        return False

# ---------------- subdomain check ----------------
def check_subdomain(sub, domain, session, timeout, verify_ssl):
    subdomain = f"{sub}.{domain}"
    if not dns_resolves(subdomain):
        return None
    urls = [f"http://{subdomain}", f"https://{subdomain}"]
    for url in urls:
        try:
            r = session.get(url, timeout=timeout, allow_redirects=True, verify=verify_ssl)
            status = r.status_code
            content_len = len(r.content) if r.content is not None else 0
            server = r.headers.get("Server", "")
            title = extract_title(r.text)
            return {"url": url.rstrip('/'), "status": status, "length": content_len, "server": server, "title": title}
        except requests.exceptions.SSLError:
            if url.startswith("https://"):
                return {"url": url.rstrip('/'), "status": "SSL_ERROR", "length": 0, "server": "", "title": ""}
        except (requests.ConnectionError, requests.Timeout, requests.TooManyRedirects):
            continue
        except Exception:
            continue
    return None

# ---------------- main enumeration ----------------
def subdomain_enum(domain, wordlist, workers, timeout, verify_ssl, report_file):
    os.makedirs(os.path.dirname(report_file) or ".", exist_ok=True)
    found_map = {}
    total = len(wordlist)
    print(Fore.YELLOW + f"\n[+] Enumerating subdomains for: {domain}  (total candidates: {total})\n" + Style.RESET_ALL)

    # wildcard detection
    rnd = random_label(14)
    if dns_resolves(f"{rnd}.{domain}"):
        print(Fore.MAGENTA + "[!] Warning: wildcard DNS appears to be present. Results may include false positives." + Style.RESET_ALL)

    session = requests.Session()
    session.headers.update({"User-Agent": "AI-VAPT-Subenum/1.0"})

    start = time.time()
    try:
        with ThreadPoolExecutor(max_workers=workers) as executor:
            future_to_sub = {executor.submit(check_subdomain, sub, domain, session, timeout, verify_ssl): sub for sub in wordlist}
            scanned = 0
            for future in as_completed(future_to_sub):
                sub = future_to_sub[future]
                scanned += 1
                try:
                    info = future.result()
                    if info:
                        host, scheme, norm_url = normalize_url(info["url"])
                        with lock:
                            # prefer https over http
                            existing = found_map.get(host)
                            if (not existing) or (existing and existing.get("url","").startswith("http://") and norm_url.startswith("https://")):
                                found_map[host] = info
                            # append raw discovery to file for persistence
                            with open(report_file, "a", encoding="utf-8") as f:
                                f.write(f"{info['url']}\tstatus={info['status']}\tlen={info['length']}\tserver={info['server']}\ttitle={info['title']}\n")
                        print(Fore.GREEN + f"[+] ({scanned}/{total}) Found: {info['url']} | {info['status']} | {info['length']} bytes | title: {info['title']}" + Style.RESET_ALL)
                    else:
                        if scanned % max(1, total//10) == 0:
                            print(Fore.BLUE + f"[-] Progress: {scanned}/{total} scanned..." + Style.RESET_ALL)
                except Exception as e:
                    if scanned % max(1, total//10) == 0:
                        print(Fore.RED + f"[!] Error scanning {sub}: {e}" + Style.RESET_ALL)

    except KeyboardInterrupt:
        print(Fore.RED + "\n[!] Interrupted by user. Writing partial results..." + Style.RESET_ALL)

    elapsed = time.time() - start
    if not found_map:
        print(Fore.RED + "\n[!] No subdomains found." + Style.RESET_ALL)
    else:
        print(Fore.CYAN + f"\n[+] Enumeration Completed in {elapsed:.1f}s! Results saved in {report_file}" + Style.RESET_ALL)
        for host in sorted(found_map.keys()):
            info = found_map[host]
            print(Fore.MAGENTA + f" - {info['url']} | {info['status']} | {info['length']} bytes | {info['server']} | {info['title']}" + Style.RESET_ALL)

# ---------------- CLI / Interactive entry ----------------
def main():
    parser = argparse.ArgumentParser(description="Subdomain enumerator (supports big .txt wordlists and CLI).")
    parser.add_argument("-d", "--domain", help="Target domain (example.com)")
    parser.add_argument("-w", "--wordlist", help="Path to external wordlist (.txt) (one entry per line)")
    parser.add_argument("--use-default", action="store_true", help=f"Use {DEFAULT_WORDLIST_PATH} in cwd if present")
    parser.add_argument("-t", "--threads", type=int, default=30, help="Max threads (default 30)")
    parser.add_argument("--timeout", type=float, default=3.0, help="Request timeout seconds (default 3.0)")
    parser.add_argument("--verify", action="store_true", help="Verify SSL certificates (default: False)")
    parser.add_argument("-o", "--output", help="Report file path (default reports/<domain>_subdomains_<ts>.txt)")
    parser.add_argument("--no-interactive", action="store_true", help="Do not prompt interactively; require domain and wordlist via CLI")
    args = parser.parse_args()

    banner()

    # Domain
    domain = args.domain
    if not domain:
        if args.no_interactive:
            print(Fore.RED + "[!] Domain required in non-interactive mode. Use -d domain.com" + Style.RESET_ALL)
            return
        domain = input(Fore.YELLOW + "Enter domain (example.com): " + Style.RESET_ALL).strip()
        if not domain:
            print(Fore.RED + "[!] No domain entered. Exiting." + Style.RESET_ALL)
            return

    # Wordlist selection
    wordlist = []
    if args.wordlist:
        if os.path.exists(args.wordlist):
            wordlist = read_external_wordlist(args.wordlist)
        else:
            print(Fore.RED + f"[!] Provided wordlist path not found: {args.wordlist}" + Style.RESET_ALL)
            if args.no_interactive:
                return
    elif args.use_default and os.path.exists(DEFAULT_WORDLIST_PATH):
        wordlist = load_default_wordlist()
    else:
        # interactive fallback: try default, offer prompt to provide path or use builtin
        if not args.no_interactive:
            use_default = None
            if os.path.exists(DEFAULT_WORDLIST_PATH):
                use_default = input(Fore.YELLOW + f"Default big_wordlist.txt found. Use it? (Y/n): " + Style.RESET_ALL).strip().lower()
                if use_default in ("", "y", "yes"):
                    wordlist = load_default_wordlist()
            if not wordlist:
                ext = input(Fore.YELLOW + "Enter path to external wordlist (or press Enter to use builtin small list): " + Style.RESET_ALL).strip()
                if ext:
                    if os.path.exists(ext):
                        wordlist = read_external_wordlist(ext)
                    else:
                        print(Fore.RED + f"[!] Path not found: {ext}. Falling back to builtin list." + Style.RESET_ALL)
                        wordlist = BUILTIN_WORDLIST.copy()
                else:
                    wordlist = BUILTIN_WORDLIST.copy()
        else:
            # non-interactive and no wordlist specified -> error
            print(Fore.YELLOW + "[!] No wordlist specified; falling back to builtin small list." + Style.RESET_ALL)
            wordlist = BUILTIN_WORDLIST.copy()

    # Merge/unique preserve order
    # If both default big file and external provided by user, we assume user provided path took precedence earlier
    # Remove duplicates while preserving order:
    seen = set()
    combined = []
    for w in wordlist:
        if w not in seen:
            seen.add(w)
            combined.append(w)

    # Threads / timeout / verify
    workers = args.threads
    timeout = args.timeout
    verify_ssl = args.verify

    # Report path
    if args.output:
        report_file = args.output
    else:
        ts = time.strftime("%Y%m%d-%H%M%S")
        os.makedirs("reports", exist_ok=True)
        report_file = os.path.join("reports", f"{domain}_subdomains_{ts}.txt")

    # Confirm in interactive mode
    if not args.no_interactive:
        print(Fore.CYAN + f"\nConfiguration:\n - domain: {domain}\n - wordlist entries: {len(combined)}\n - threads: {workers}\n - timeout: {timeout}\n - verify_ssl: {verify_ssl}\n - report: {report_file}\n" + Style.RESET_ALL)
        cont = input(Fore.YELLOW + "Start scan? (Y/n): " + Style.RESET_ALL).strip().lower()
        if cont not in ("", "y", "yes"):
            print(Fore.RED + "Cancelled." + Style.RESET_ALL)
            return

    # Run enumeration
    subdomain_enum(domain, combined, workers, timeout, verify_ssl, report_file)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n" + Fore.RED + "[!] Exited by user." + Style.RESET_ALL)
