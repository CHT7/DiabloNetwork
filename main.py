import os
import subprocess
import threading
import time
import sys
import requests
import ipaddress
from concurrent.futures import ThreadPoolExecutor
from colorama import Fore, init
from tabulate import tabulate

init()

G = Fore.LIGHTGREEN_EX
R = Fore.LIGHTRED_EX
Cyn = Fore.LIGHTCYAN_EX
Ylw = Fore.LIGHTYELLOW_EX

banner = r"""

     __     _                      _      __                 
  /\ \ \___| |___      _____  _ __| | __ / _\ ___ __ _ _ __  
 /  \/ / _ \ __\ \ /\ / / _ \| '__| |/ / \ \ / __/ _` | '_ \ 
/ /\  /  __/ |_ \ V  V / (_) | |  |   <  _\ \ (_| (_| | | | |
\_\ \/ \___|\__| \_/\_/ \___/|_|  |_|\_\ \__/\___\__,_|_| |_|  
----------------------- [+] DDIABLO ------------------------

"""
    
def print_banner():
    print(Cyn + banner)

def get_network_from_ip():
    try:
        if os.name == 'nt':  
            ipconfig_output = subprocess.check_output("ipconfig", encoding="utf-8")
            for line in ipconfig_output.splitlines():
                if "IPv4" in line:  
                    ip = line.split(":")[1].strip()
                    return ip + "/24" 
        else: 
            ipconfig_output = subprocess.check_output("ip a", shell=True, encoding="utf-8")
            for line in ipconfig_output.splitlines():
                if "inet " in line:  
                    ip = line.split()[1]
                    return ip.split('/')[0] + "/24" 
    except Exception as e:
        print(R + "Không thể lấy thông tin mạng!")
        sys.exit(1)

def get_user_input():
    subnet_input = input("Nhập subnet (ví dụ: 192.168.1.0/24) hoặc để trống để tự động lấy subnet: ")
    if not subnet_input:
        subnet_input = get_network_from_ip()
        print(G + f"Đã tự động lấy subnet: {subnet_input}")
    try:
        return ipaddress.ip_network(subnet_input, strict=False)
    except ValueError:
        print(R + "Subnet không hợp lệ! Dùng định dạng CIDR như 192.168.1.0/24")
        sys.exit(1)

def scan_ip(ip):
    ip_str = str(ip)
    ping_cmd = f"ping -c1 -s1 {ip_str}"
    ping_result = os.popen(ping_cmd).read()
    
    if any(x in ping_result for x in ["Unreachable", "timed out", "100%"]):
        return None

    # Get MAC Address
    arp_cmd = f"arp -a {ip_str}"
    arp_result = os.popen(arp_cmd).read()
    
    if ":" in arp_result:
        mac_start = arp_result.find(":")
        mac = arp_result[mac_start-2:mac_start+15].strip()
    else:
        iface_info = os.popen("ip address show wlan0").read()
        mac_start = iface_info.find("link/ether")
        mac = iface_info[mac_start+11:mac_start+28].strip() if mac_start != -1 else "[Not Found]"

    # Get Vendor
    vendor = "[Not Found]"
    try:
        response = requests.get(f"https://macvendors.com/query/{mac}")
        if response.status_code == 200:
            vendor = response.text.strip()
    except requests.RequestException:
        vendor = "[Error]"

    return [ip_str, mac, vendor]

def main():
    os.system('cls') if os.name == 'nt' else os.system('clear')
    print_banner()
    network = get_user_input()
    input("Nhấn 'Enter' để bắt đầu quét...")

    with ThreadPoolExecutor(max_workers=100) as executor:
        results = list(executor.map(scan_ip, network.hosts()))

    results = [r for r in results if r is not None]

    os.system('cls') if os.name == 'nt' else os.system('clear')
    print_banner()

    if results:
        print(Cyn + "\nKết Quả:\n")
        print(G + tabulate(results, headers=["IP", "MAC Address", "Vendor"], tablefmt="grid"))
    else:
        print(R + "\nKhông tìm thấy thiết bị nào trong mạng!")

    input("\nNhấn Enter để thoát...")

if __name__ == "__main__":
    main()
