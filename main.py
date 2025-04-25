import socket
import os
import sys
import subprocess
import ipaddress
import requests
import re
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import Fore, init
from tabulate import tabulate
import shutil
import platform

init(autoreset=True)

G = Fore.LIGHTGREEN_EX
R = Fore.LIGHTRED_EX
C = Fore.LIGHTCYAN_EX
Y = Fore.LIGHTYELLOW_EX

vendor_cache = {}

def print_banner():
    print(C + r"""
     __     _                      _      __                 
  /\ \ \___| |___      _____  _ __| | __ / _\ ___ __ _ _ __  
 /  \/ / _ \ __\ \ /\ / / _ \| '__| |/ / \ \ / __/ _` | '_ \ 
/ /\  /  __/ |_ \ V  V / (_) | |  |   <  _\ \ (_| (_| | | | |
\_\ \/ \___|\__| \_/\_/ \___/|_|  |_|\_\ \__/\___\__,_|_| |_|  
------------------ [+] DDIABLO ------------------------------
""")

def get_local_subnet():
    try:
        if os.name == 'nt':
            output = subprocess.check_output("ipconfig", encoding="utf-8")
            for line in output.splitlines():
                if "IPv4" in line:
                    ip = line.split(":")[1].strip()
                    return ip + "/24"
        else:
            output = subprocess.check_output("ifconfig", shell=True, encoding="utf-8")
            for line in output.splitlines():
                if "inet " in line and not "127.0.0.1" in line:
                    ip = line.split()[1]
                    return ip.split('/')[0] + "/24"
    except Exception as e:
        print(R + f"Không thể lấy subnet mạng. Lỗi: {str(e)}")
        sys.exit(1)

def has_nmap():
    return shutil.which("nmap") is not None

def is_termux():
    return "com.termux" in os.getenv("PREFIX", "")

def get_mac(ip):
    if os.name == "nt":
        arp_out = subprocess.getoutput(f"arp -a {ip}")
    else:
        arp_out = subprocess.getoutput(f"ip neigh show {ip}")

    mac_match = re.search(r"(([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2}))", arp_out)
    return mac_match.group(0) if mac_match else "[Unknown]"

def get_vendor(mac):
    mac = mac.upper()
    if mac in vendor_cache:
        return vendor_cache[mac]

    try:
        r = requests.get(f"https://macvendors.com/query/{mac}", timeout=2)
        if r.status_code == 200:
            vendor = r.text.strip()
            vendor_cache[mac] = vendor
            return vendor
    except:
        pass
    return "[Not Found]"

def get_mac_and_vendor_with_nmap(ip):
    try:
        output = subprocess.getoutput(f"nmap -sP {ip}")
        mac_match = re.search(r"MAC Address: ([0-9A-F:]{17}) \((.*?)\)", output)
        if mac_match:
            mac = mac_match.group(1)
            vendor = mac_match.group(2)
            return mac, vendor
    except:
        pass
    return "[Unknown]", "[Not Found]"

def guess_device(vendor, ttl):
    vendor = vendor.lower()
    if ttl:
        ttl = int(ttl)
        if ttl <= 64:
            if "apple" in vendor:
                return "iOS/macOS"
            elif "linux" in vendor:
                return "Linux"
            return "Android/Unix-like"
        elif ttl <= 128:
            if "apple" in vendor:
                return "iOS/macOS"
            return "Windows"
        elif ttl <= 255:
            return "Router/Embedded"
    return "Unknown"

def resolve_hostname(ip):
    try:
        # Ưu tiên dùng nbtscan nếu có sẵn (Termux)
        if os.name != 'nt':
            nbtscan_result = subprocess.getoutput(f"nbtscan -s : {ip}")
            for line in nbtscan_result.splitlines():
                if ip in line:
                    parts = line.split(":")
                    if len(parts) >= 2:
                        name = parts[1].strip()
                        if name and name.lower() != 'unknown':
                            return name
        # Nếu không thì fallback sang DNS
        hostname = socket.gethostbyaddr(ip)[0]
        if ".non-exists.ptr.local" in hostname or ip in hostname:
            return "[Unknown]"
        return hostname
    except:
        return "[Unknown]"

def scan_ip(ip, args):
    ip = str(ip)
    ping_cmd = f"ping -c1 -W1 {ip}" if os.name != 'nt' else f"ping -n 1 -w 1000 {ip}"
    result = subprocess.getoutput(ping_cmd)

    if any(x in result.lower() for x in ["unreachable", "timed out", "100%"]):
        return None if not args.show_offline else [ip, "[Offline]", "-", "-", "-", "-"]

    ttl = None
    for line in result.splitlines():
        if "ttl=" in line.lower():
            ttl_part = line.lower().split("ttl=")[-1].split()[0]
            try:
                ttl = int(ttl_part)
            except:
                ttl = None
            break

    if args.ping_only:
        return [ip, "[Ping Only]", "-", "-", str(ttl or "?"), "-"]

    hostname = resolve_hostname(ip)

    # >>> Tự động ưu tiên dùng nmap nếu có hoặc đang ở Termux
    use_nmap = is_termux() or has_nmap()
    if use_nmap:
        mac, vendor = get_mac_and_vendor_with_nmap(ip)
    else:
        mac = get_mac(ip)
        vendor = get_vendor(mac) if mac not in ["[Unknown]", "ff:ff:ff:ff:ff:ff"] else "[Not Found]"

    device_type = guess_device(vendor, ttl)

    return [ip, hostname, mac, vendor, str(ttl or "?"), device_type]

def parse_args():
    parser = argparse.ArgumentParser(description="Network Scanner")
    parser.add_argument("--ping-only", action="store_true", help="Chỉ ping, không lấy MAC/vendor")
    parser.add_argument("--show-offline", action="store_true", help="Hiển thị cả thiết bị offline")
    return parser.parse_args()

def print_results_in_pairs(results):
    labels = ["IP", "Host", "MAC", "Vendor", "TTL", "Thiết bị"]
    pairs = [results[i:i+2] for i in range(0, len(results), 2)]
    label_width = max(len(lbl) for lbl in labels)

    for idx, pair in enumerate(pairs):
        blocks = []

        for i, r in enumerate(pair):
            title = f" Thiết bị #{idx*2 + i + 1} "
            col_width = max(len(str(v)) for v in r)
            total_width = label_width + col_width + 7

            block = []
            block.append("╔" + "═" * ((total_width - len(title)) // 2) + title + "═" * (total_width - (total_width - len(title)) // 2 - len(title)) + "╗")
            for label, value in zip(labels, r):
                line = f"{label:<{label_width}} : {value}"
                block.append(f"║ {line:<{total_width}}║")
            block.append("╚" + "═" * total_width + "╝")
            blocks.append(block)

        # In hai block cạnh nhau
        for lines in zip(*blocks):
            print(G + lines[0] + "  " + (lines[1] if len(lines) > 1 else ""))

        print()

def main():
    args = parse_args()
    os.system('cls' if os.name == 'nt' else 'clear')
    print_banner()

    subnet = get_local_subnet()
    print(G + f"Đang quét mạng: {subnet}\n")

    network = list(ipaddress.ip_network(subnet, strict=False).hosts())

    results = []
    total = len(network)

    with ThreadPoolExecutor(max_workers=100) as executor:
        future_to_ip = {executor.submit(scan_ip, ip, args): ip for ip in network}
        for i, future in enumerate(as_completed(future_to_ip), 1):
            ip = future_to_ip[future]
            try:
                result = future.result()
                if result:
                    results.append(result)
            except Exception as e:
                pass
            percent = (i / total) * 100
            print(f"{C}[{i}/{total}] ({percent:.1f}%)", end='\r')

    os.system('cls' if os.name == 'nt' else 'clear')
    print_banner()

    if results:
        print(C + f"\nTổng thiết bị phát hiện: {len(results)}\n")
        if is_termux():
            print_results_in_pairs(results)
        elif os.name == 'nt':
            print(G + tabulate(
                [[i+1] + r for i, r in enumerate(results)],
                headers=["#", "IP", "Host", "MAC", "Vendor", "TTL", "Thiết bị"],
                tablefmt="double_outline"
            ))
        else:
            labels = ["IP", "Host", "MAC", "Vendor", "TTL", "Thiết bị"]
            col_width = max(
                max(len(str(item[i])) for item in results)
                for i in range(len(labels))
            )
            label_width = max(len(lbl) for lbl in labels)

            total_width = label_width + col_width + 7

            for i, r in enumerate(results, 1):
                title = f" Thiết bị #{i} "
                print(G + "╔" + "═" * ((total_width - len(title)) // 2) + title + "═" * (total_width - (total_width - len(title)) // 2 - len(title)) + "╗")

                for label, value in zip(labels, r):
                    line = f"{label:<{label_width}} : {value}"
                    print(G + f"║ {line:<{total_width}}║")

                print(G + "╚" + "═" * total_width + "╝\n")

if __name__ == "__main__":
    main()