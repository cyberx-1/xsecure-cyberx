#!/usr/bin/env python3
# ========================================================
# Title: XSecure Python Scanner (XSS, SQLi, API, LFI)
# Author: CyberX | Mohammad Almahamid
# License: Open Source (Attribution Required)
# Year: 2025
# ========================================================

import requests
import sys
import urllib.parse
from colorama import init, Fore

init(autoreset=True)

def load_payloads(file_path):
    with open(file_path, 'r', encoding='utf-8') as f:
        return [line.strip() for line in f if line.strip()]

def scan_xss(url, payloads):
    print("[*] Starting XSS scan...")
    for p in payloads:
        target = url.replace("FUZZ", urllib.parse.quote(p))
        try:
            r = requests.get(target, timeout=10)
            if p in r.text:
                print(Fore.GREEN + f"[+] XSS Confirmed: {p}")
                print(Fore.GREEN + f"    URL: {target}")
            else:
                print(Fore.RED + f"[-] XSS Not found: {p}")
        except Exception as e:
            print(Fore.RED + f"[Error] XSS payload {p} request failed: {e}")

def scan_sqli(url, payloads):
    print("[*] Starting SQLi scan...")
    error_signatures = [
        "you have an error in your sql syntax",
        "warning: mysql",
        "unclosed quotation mark after the character string",
        "quoted string not properly terminated",
        "mysql_fetch",
        "syntax error",
        "sql syntax",
        "odbc",
        "ora-",
        "psql",
    ]
    for p in payloads:
        target = url.replace("FUZZ", urllib.parse.quote(p))
        try:
            r = requests.get(target, timeout=10)
            if any(sig.lower() in r.text.lower() for sig in error_signatures):
                print(Fore.GREEN + f"[+] SQLi Detected with payload: {p}")
                print(Fore.GREEN + f"    URL: {target}")
            else:
                print(Fore.RED + f"[-] SQLi Not found: {p}")
        except Exception as e:
            print(Fore.RED + f"[Error] SQLi payload {p} request failed: {e}")

def scan_api(url_base, payloads):
    print("[*] Starting API Endpoint Discovery...")
    for p in payloads:
        target = url_base.rstrip("/") + p
        try:
            r = requests.get(target, timeout=10)
            if r.status_code in range(200, 400) and "{" in r.text:
                print(Fore.GREEN + f"[+] API endpoint found: {target} (Status: {r.status_code})")
            else:
                print(Fore.RED + f"[-] API endpoint not found: {target} (Status: {r.status_code})")
        except Exception as e:
            print(Fore.RED + f"[Error] API request to {target} failed: {e}")

def scan_lfi(url, payloads):
    print("[*] Starting LFI scan...")
    for p in payloads:
        target = url.replace("FUZZ", urllib.parse.quote(p))
        try:
            r = requests.get(target, timeout=10)
            indicators = [
                "root:x",
                "[boot]",
                "root:/",
                "index of /",
                "phpinfo()",
                "failed to open stream",
                "no such file or directory",
            ]
            if any(ind.lower() in r.text.lower() for ind in indicators):
                print(Fore.GREEN + f"[+] LFI Detected with payload: {p}")
                print(Fore.GREEN + f"    URL: {target}")
            else:
                print(Fore.RED + f"[-] LFI Not found: {p}")
        except Exception as e:
            print(Fore.RED + f"[Error] LFI payload {p} request failed: {e}")

def main():
    if len(sys.argv) != 5:
        print("Usage: python3 scanner.py <url_with_FUZZ_or_base> <scan_type> <payloads_file> <api_base_for_api>")
        print("scan_type: xss | sqli | api | lfi")
        print("For api scan, use the base url (without FUZZ) as first argument and api_base_for_api as '.' or '-' if not used")
        sys.exit(1)

    url = sys.argv[1]
    scan_type = sys.argv[2].lower()
    payload_file = sys.argv[3]
    api_base = sys.argv[4]

    payloads = load_payloads(payload_file)

    if scan_type == "xss":
        scan_xss(url, payloads)
    elif scan_type == "sqli":
        scan_sqli(url, payloads)
    elif scan_type == "api":
        if api_base in ['.', '-']:
            api_base = url
        scan_api(api_base, payloads)
    elif scan_type == "lfi":
        scan_lfi(url, payloads)
    else:
        print(f"[!] Unknown scan type: {scan_type}")

if __name__ == "__main__":
    main()
