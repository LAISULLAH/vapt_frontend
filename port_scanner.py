import os
import sys
import socket
import nmap
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

# ===================== Banner =====================
def banner():
    print(Fore.RED + r"""
    _    ___   _____ _____    _    __  __ 
   / \  |_ _| |_   _| ____|  / \  |  \/  |
  / _ \  | |    | | |  _|   / _ \ | |\/| |
 / ___ \ | |    | | | |___ / ___ \| |  | |
/_/   \_\___|   |_| |_____/_/   \_\_|  |_|

==================================================
     AI-Powered VAPT Toolkit
==================================================
""" + Style.RESET_ALL)

# ===================== Port Scanning =====================
def port_scanner():
    target = input("\nEnter URL/IP: ").strip()
    if not target:
        print(Fore.RED + "[!] No target entered." + Style.RESET_ALL)
        return

    try:
        # Resolve hostname to IP
        ip = socket.gethostbyname(target)
        print(Fore.GREEN + f"\n[+] Scanning target: {target} ({ip})\n" + Style.RESET_ALL)
    except socket.gaierror:
        print(Fore.RED + f"[!] Invalid host: {target}" + Style.RESET_ALL)
        return

    try:
        nm = nmap.PortScanner()
        # Full intense scan (-sS -sV -O)
        nm.scan(ip, arguments="-sS -sV -O")

        if not nm.all_hosts():
            print(Fore.RED + "[!] No hosts found." + Style.RESET_ALL)
            return

        for host in nm.all_hosts():
            print(Fore.CYAN + f"Host: {host} ({nm[host].hostname()})" + Style.RESET_ALL)
            print(Fore.CYAN + f"State: {nm[host].state()}\n" + Style.RESET_ALL)

            if 'tcp' in nm[host]:
                for port in nm[host]['tcp']:
                    state = nm[host]['tcp'][port]['state']
                    name = nm[host]['tcp'][port]['name']
                    product = nm[host]['tcp'][port].get('product', '')
                    version = nm[host]['tcp'][port].get('version', '')
                    extrainfo = nm[host]['tcp'][port].get('extrainfo', '')

                    print(Fore.YELLOW + f"Port: {port} | State: {state} | Service: {name} "
                          f"| Product: {product} {version} {extrainfo}" + Style.RESET_ALL)

    except Exception as e:
        print(Fore.RED + f"[!] Error: {e}" + Style.RESET_ALL)


# Run directly
if __name__ == "__main__":
    banner()
    port_scanner()

