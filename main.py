import os
import subprocess
from colorama import Fore, Style
from ultra_redteam_v6_1 import main_attaks

def banner():
    print(Fore.RED + r"""
    _    ___   _____ _____    _    __  __
   / \  |_ _| |_   _| ____|  / \  |  \/  |
  / _ \  | |    | | |  _|   / _ \ | |\/| |
 / ___ \ | |    | | | |___ / ___ \| |  | |
/_/   \_\___|   |_| |_____/_/   \_\_|  |_|

==================================================
     AI-Powered VAPT Toolkit - Subdomain Enum
==================================================
""" + Style.RESET_ALL)

def port_scanner_menu():
    while True:
        print(Fore.CYAN + "\n[ Port Scanning Module ]\n" + Style.RESET_ALL)
        print(Fore.WHITE + "1. Quick Scan (Top 100 Ports)")
        print("2. Full TCP Scan (1–65535)")
        print("3. Service & Version Detection")
        print("4. Aggressive Scan (OS + Scripts)")
        print("5. UDP Scan")
        print("6. Stealth SYN Scan")
        print("7. Script Scan (Default NSE Scripts)")
        print("8. OS Detection Only")
        print("9. Custom Port Range Scan")
        print("10. Save Reports (TXT, XML, HTML, CSV, JSON)")
        print("11. Back to Main Menu\n")

        choice = input(Fore.RED + "Enter Port Scan option: " + Fore.WHITE).strip()
        os.system("clear")

        if choice == "1":
            target = input(Fore.RED + "Enter target IP/Domain: " + Fore.WHITE).strip()
            print(Fore.YELLOW + f"[+] Running Quick Scan on {target}..." + Style.RESET_ALL)
            os.system(f"nmap --top-ports 100 {target}")

        elif choice == "2":
            target = input(Fore.RED + "Enter target IP/Domain: " + Fore.WHITE).strip()
            print(Fore.YELLOW + f"[+] Running Full TCP Scan on {target}..." + Style.RESET_ALL)
            os.system(f"nmap -p- {target}")

        elif choice == "3":
            target = input(Fore.RED + "Enter target IP/Domain: " + Fore.WHITE).strip()
            print(Fore.YELLOW + f"[+] Running Service & Version Detection on {target}..." + Style.RESET_ALL)
            os.system(f"nmap -sV {target}")

        elif choice == "4":
            target = input(Fore.RED + "Enter target IP/Domain: " + Fore.WHITE).strip()
            print(Fore.YELLOW + f"[+] Running Aggressive Scan on {target}..." + Style.RESET_ALL)
            os.system(f"nmap -A {target}")

        elif choice == "5":
            target = input(Fore.RED + "Enter target IP/Domain: " + Fore.WHITE).strip()
            print(Fore.YELLOW + f"[+] Running UDP Scan on {target}..." + Style.RESET_ALL)
            os.system(f"nmap -sU --top-ports 50 {target}")

        elif choice == "6":
            target = input(Fore.RED + "Enter target IP/Domain: " + Fore.WHITE).strip()
            print(Fore.YELLOW + f"[+] Running Stealth SYN Scan on {target}..." + Style.RESET_ALL)
            os.system(f"sudo nmap -sS {target}")

        elif choice == "7":
            target = input(Fore.RED + "Enter target IP/Domain: " + Fore.WHITE).strip()
            print(Fore.YELLOW + f"[+] Running Script Scan on {target}..." + Style.RESET_ALL)
            os.system(f"nmap -sC {target}")

        elif choice == "8":
            target = input(Fore.RED + "Enter target IP/Domain: " + Fore.WHITE).strip()
            print(Fore.YELLOW + f"[+] Running OS Detection Scan on {target}..." + Style.RESET_ALL)
            os.system(f"nmap -O {target}")

        elif choice == "9":
            target = input(Fore.RED + "Enter target IP/Domain: " + Fore.WHITE).strip()
            ports = input(Fore.RED + "Enter custom port range (e.g. 20-1000): " + Fore.WHITE).strip()
            print(Fore.YELLOW + f"[+] Running Custom Port Scan on {target}, Ports: {ports}..." + Style.RESET_ALL)
            os.system(f"nmap -p {ports} {target}")

        elif choice == "10":
            target = input(Fore.RED + "Enter target IP/Domain: " + Fore.WHITE).strip()
            os.makedirs("reports", exist_ok=True)

            txt_report = os.path.join("reports", f"{target}_scan.txt")
            xml_report = os.path.join("reports", f"{target}_scan.xml")
            html_report = os.path.join("reports", f"{target}_scan.html")
            csv_report = os.path.join("reports", f"{target}_scan.gnmap")
            json_report = os.path.join("reports", f"{target}_scan.xml")  # XML works as JSON-like

            print(Fore.YELLOW + f"[+] Saving reports for {target}..." + Style.RESET_ALL)
            os.system(f"nmap -sV -A {target} -oN {txt_report} -oX {xml_report} -oG {csv_report}")
            os.system(f"xsltproc {xml_report} -o {html_report}")

            print(Fore.GREEN + f"""
[+] Reports saved:
   TXT : {txt_report}
   XML : {xml_report}
   HTML: {html_report}
   CSV : {csv_report}
   JSON: {json_report} (parse XML)
""" + Style.RESET_ALL)

        elif choice == "11":
            break

        else:
            print(Fore.RED + "Invalid choice, try again!" + Style.RESET_ALL)


def main_menu():
    while True:
        banner()
        print(Fore.RED + "Choose an option:\n")
        print(Fore.WHITE + "1. Port Scanning")
        print("2. Subdomain Enumeration")
        print("3. Vulnerability Scan (AI)")   
        print("4. OSINT")
        print("5. Attacking Tools")
        print("6. Exit\n")

        choice = input(Fore.RED + "Enter choice: " + Fore.WHITE).strip()
        os.system("clear")

        if choice == "1":
            port_scanner_menu()

        elif choice == "2":
            if os.path.exists("subdomain_enum.py"):
                os.system("python3 subdomain_enum.py")
            else:
                print(Fore.RED + "subdomain_enum.py not found!" + Style.RESET_ALL)

        elif choice == "3":
            if os.path.exists("vul_scan.py"):
                os.system("python3 vul_scan.py")
            else:
                print(Fore.RED + "vul_scan.py not found!" + Style.RESET_ALL)

        elif choice == "4":
            if os.path.exists("osint.py"):
                target = input(Fore.RED + "Enter domain for OSINT scan: " + Fore.WHITE).strip()
                os.system(f"python3 osint.py {target}")
                report_file = os.path.join("reports", f"{target}.txt")
                if os.path.exists(report_file):
                    print(Fore.GREEN + f"[+] Opening report: {report_file}" + Style.RESET_ALL)
                    subprocess.run(["less", report_file])
                else:
                    print(Fore.RED + "[-] Report not found!" + Style.RESET_ALL)
            else:
                print(Fore.RED + "osint.py not found!" + Style.RESET_ALL)

        elif choice == "5":
            main_attaks()

        elif choice == "6":
            print(Fore.RED + "Exiting... Bye!" + Style.RESET_ALL)
            exit()

        else:
            print(Fore.RED + "Invalid choice, try again!" + Style.RESET_ALL)


if __name__ == "__main__":
    main_menu()
