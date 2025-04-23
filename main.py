import os
import sys
import subprocess
import ipaddress
import requests
from concurrent.futures import ThreadPoolExecutor
from colorama import Fore, init
from tabulate import tabulate

init(autoreset=True)

G = Fore.LIGHTGREEN_EX
R = Fore.LIGHTRED_EX
C = Fore.LIGHTCYAN_EX
Y = Fore.LIGHTYELLOW_EX

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
            # Thay thế 'ip a' bằng 'ifconfig' cho Termux
            output = subprocess.check_output("ifconfig", shell=True, encoding="utf-8")
            for line in output.splitlines():
                if "inet " in line and not "127.0.0.1" in line:
                    ip = line.split()[1]
                    return ip.split('/')[0] + "/24"
    except Exception as e:
        print(R + f"Không thể lấy subnet mạng. Lỗi: {str(e)}")
        sys.exit(1)

def scan_ip(ip):
    ip = str(ip)
    ping_cmd = f"ping -c1 -W1 {ip}" if os.name != 'nt' else f"ping -n 1 -w 1000 {ip}"
    result = subprocess.getoutput(ping_cmd)

    if any(x in result.lower() for x in ["unreachable", "timed out", "100%"]):
        return None

    ttl = None
    for line in result.splitlines():
        if "ttl=" in line.lower():
            ttl_part = line.lower().split("ttl=")[-1].split()[0]
            try:
                ttl = int(ttl_part)
            except:
                ttl = None
            break

    arp_cmd = f"arp -a {ip}"
    arp_out = subprocess.getoutput(arp_cmd)

    mac = "[Unknown]"
    for line in arp_out.splitlines():
        if ip in line:
            for part in line.split():
                if ":" in part or "-" in part:
                    mac = part.strip()
                    break
            break

    vendor = "[Not Found]"
    try:
        if mac not in ["[Unknown]", "ff:ff:ff:ff:ff:ff"]:
            r = requests.get(f"https://macvendors.com/query/{mac}", timeout=2)
            if r.status_code == 200:
                vendor = r.text.strip()
    except:
        pass

    device_type = guess_device(vendor, ttl)

    return [ip, mac, vendor, str(ttl or "?"), device_type]

def guess_device(vendor, ttl):
    vendor = vendor.lower()
    
    # Thêm điều kiện nhận diện TTL 64 là macOS/Linux hoặc các thiết bị mạng
    if ttl == 64:
        if "apple" in vendor:
            return "Apple (macOS)"
        elif "linux" in vendor:
            return "Linux"
    
    # Các điều kiện khác
    if "apple" in vendor:
        return "Apple"
    if "samsung" in vendor or "huawei" in vendor or "xiaomi" in vendor:
        return "Android"
    if "microsoft" in vendor or (ttl and int(ttl) in [128, 127]):
        return "Windows"
    
    return "Unknown"

def main():
    os.system('cls' if os.name == 'nt' else 'clear')
    print_banner()

    subnet = get_local_subnet()
    print(G + f"Đang quét mạng: {subnet}\n")

    network = ipaddress.ip_network(subnet, strict=False)
    with ThreadPoolExecutor(max_workers=100) as executor:
        results = list(executor.map(scan_ip, network.hosts()))

    results = [r for r in results if r]

    os.system('cls' if os.name == 'nt' else 'clear')
    print_banner()

    if results:
        print(C + f"\nTổng thiết bị đang kết nối: {len(results)}\n")
        print(G + tabulate(
            [[i+1] + r for i, r in enumerate(results)],
            headers=["#", "IP", "MAC", "Vendor", "TTL", "Thiết bị"],
            tablefmt="grid"
        ))
    else:
        print(R + "Không phát hiện thiết bị nào!")

if __name__ == "__main__":
    main()
