import socket
import os
import sys
import subprocess
import ipaddress
import requests
import re
import argparse
import threading
import time
import json
import csv
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import Fore, Style, init
from tabulate import tabulate


# Khởi tạo màu sắc
init(autoreset=True)

# --- CONFIGURATION ---
LOCAL_VENDOR_DB = {
    # Apple
    "BC:D0:74": "Apple", "F0:18:98": "Apple", "DC:A9:04": "Apple", "88:E9:FE": "Apple",
    # Samsung
    "2C:F0:5D": "Samsung", "AC:5F:3E": "Samsung", "D0:13:FD": "Samsung",
    # Virtual/PC
    "00:1A:79": "Nutanix", "00:50:56": "VMware", "00:0C:29": "VMware", "00:15:5D": "Hyper-V",
    # IoT/Pi
    "B8:27:EB": "Raspberry Pi", "DC:A6:32": "Raspberry Pi", "E4:5F:01": "Raspberry Pi",
    # Phones/Others
    "00:D8:61": "Xiaomi", "64:CC:2E": "Xiaomi",
    "18:C0:4D": "Intel", "00:1B:21": "Intel",
    # Router/Camera
    "EC:55:1C": "Huawei", "A4:2B:B0": "TP-Link", "F4:F2:6D": "TP-Link",
    "10:62:EB": "Hikvision", "BC:32:5E": "Dahua"
}

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 53: "DNS",
    80: "HTTP", 443: "HTTPS", 445: "SMB", 3389: "RDP",
    554: "RTSP(Camera)", 8080: "HTTP-Proxy"
}

class NetworkScanner:
    def __init__(self):
        self.vendor_cache = {}
        self.lock = threading.Lock()
        
    def banner(self):
        os.system('cls' if os.name == 'nt' else 'clear')
        print(Fore.CYAN + Style.BRIGHT + r"""
   ___  _      __   __     _  __    __                  __  
  / _ \(_)__ _/ /  / /__  / |/ /__ / /__    _____  ____/ /__
 / // / / _ `/ _ \/ / _ \/    / -_) __/ |/|/ / _ \/ __/  '_/
/____/_/\_,_/_.__/_/\___/_/|_/\__/\__/|__,__/\___/_/ /_/\_\ 
                                                            
-------- [+] V3.0 GOD MODE EDITION [+] --------
    """)

    def get_local_ip(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(('8.8.8.8', 1))
            IP = s.getsockname()[0]
        except Exception:
            IP = '127.0.0.1'
        finally:
            s.close()
        return IP

    def get_mac_address(self, ip):
        if ip == self.get_local_ip():
            return "Local Interface"
        try:
            if os.name == "nt":
                cmd = f"arp -a {ip}"
                pattern = r"(([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2}))"
            else:
                cmd = f"ip neigh show {ip}"
                pattern = r"(([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2}))"

            output = subprocess.getoutput(cmd)
            match = re.search(pattern, output)
            if match:
                return match.group(0).replace("-", ":").upper()
        except:
            pass
        return None

    def get_vendor(self, mac):
        if not mac or mac == "Local Interface":
            return "-"
        
        # Check Randomized MAC (Privacy)
        clean_mac = mac.replace(":", "").replace("-", "").upper()
        if len(clean_mac) == 12:
            second_char = clean_mac[1]
            if second_char in ['2', '6', 'A', 'E']:
                return "Unknown (Randomized)"

        # Check Local DB (OUI 3 bytes)
        oui = mac[:8].upper()
        for prefix, name in LOCAL_VENDOR_DB.items():
            if mac.startswith(prefix):
                return name

        # Check API
        if mac in self.vendor_cache:
            return self.vendor_cache[mac]

        try:
            r = requests.get(f"https://api.macvendors.com/{mac}", timeout=1)
            if r.status_code == 200:
                vendor = r.text.strip()
                with self.lock:
                    self.vendor_cache[mac] = vendor
                return vendor
        except:
            pass
        return "Unknown"

    def grab_http_banner(self, ip, port):
        """Lấy thông tin Server header từ HTTP"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            s.connect((ip, port))
            s.send(b"HEAD / HTTP/1.0\r\n\r\n")
            response = s.recv(1024).decode('utf-8', errors='ignore')
            s.close()
            for line in response.split('\r\n'):
                if line.startswith("Server:"):
                    return line.split("Server:")[1].strip()[:15] # Lấy ngắn gọn
        except:
            pass
        return None

    def scan_ports_and_banner(self, ip):
        """Quét cổng và lấy banner dịch vụ"""
        open_ports = []
        info_extra = []
        
        for port, name in COMMON_PORTS.items():
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.2) 
            result = s.connect_ex((ip, port))
            if result == 0:
                open_ports.append(str(port))
                # Đặc biệt: Nếu là port 80/8080, thử lấy tên Web Server
                if port in [80, 8080]:
                    banner = self.grab_http_banner(ip, port)
                    if banner:
                        info_extra.append(f"Web:{banner}")
            s.close()
            
        port_str = ",".join(open_ports) if open_ports else ""
        extra_str = " | ".join(info_extra)
        return open_ports, port_str, extra_str

    def guess_os_enhanced(self, ttl, open_ports):
        """Đoán OS dựa trên TTL VÀ Port"""
        os_guess = "Unknown"
        
        # 1. Dựa trên TTL
        if ttl:
            ttl = int(ttl)
            if ttl <= 64: os_guess = "Linux/Android/iOS"
            elif ttl <= 128: os_guess = "Windows"
            elif ttl <= 255: os_guess = "Cisco/Router"
        
        # 2. Tinh chỉnh dựa trên Port đặc thù
        if 445 in open_ports or 3389 in open_ports:
            os_guess = "Windows"
        elif 22 in open_ports:
            if os_guess == "Windows": os_guess = "Windows (SSH)" # Hiếm
            else: os_guess = "Linux/Unix"
            
        return os_guess

    def get_device_icon(self, vendor, os_guess, open_ports):
        """Gán Icon cho thiết bị"""
        vendor = vendor.lower()
        os_guess = os_guess.lower()
        
        if "camera" in vendor or "hikvision" in vendor or "dahua" in vendor or 554 in open_ports:
            return "📷 Camera"
        if "apple" in vendor or "iphone" in vendor or "ipad" in vendor:
            return "🍎 Apple"
        if "samsung" in vendor or "android" in os_guess or "xiaomi" in vendor:
            return "📱 Mobile"
        if "windows" in os_guess:
            return "💻 PC/Lap"
        if "linux" in os_guess and 22 in open_ports:
            return "🐧 Linux Srv"
        if "router" in os_guess or "gateway" in vendor or "huawei" in vendor:
            return "🌐 Router"
        return "🔌 Device"

    def ping_and_scan(self, ip, args):
        # 1. Ping
        param = '-n' if os.name == 'nt' else '-c'
        timeout_param = '-w' if os.name == 'nt' else '-W'
        timeout_val = '1000' if os.name == 'nt' else '1'
        
        # Windows: Ẩn window ping để không bị nháy
        if os.name == 'nt':
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            proc = subprocess.Popen(['ping', param, '1', timeout_param, timeout_val, str(ip)], 
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, startupinfo=startupinfo, encoding='utf-8')
        else:
            proc = subprocess.Popen(['ping', param, '1', timeout_param, timeout_val, str(ip)], 
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, encoding='utf-8')
        out, _ = proc.communicate()

        if proc.returncode != 0:
            return None

        # 2. TTL extraction
        ttl = None
        ttl_match = re.search(r"ttl=(\d+)", out, re.IGNORECASE)
        if ttl_match:
            ttl = ttl_match.group(1)

        # 3. Info Gathering
        hostname = "-"
        try:
            hostname = socket.gethostbyaddr(str(ip))[0]
        except:
            pass

        mac = self.get_mac_address(str(ip))
        vendor = self.get_vendor(mac)
        
        # 4. Port Scan (Luôn quét nhanh các cổng critical để nhận diện OS chính xác hơn)
        open_ports_list, ports_str, banner_info = self.scan_ports_and_banner(str(ip))
        
        # 5. Finalize Logic
        os_guess = self.guess_os_enhanced(ttl, [int(p) for p in open_ports_list])
        icon_type = self.get_device_icon(vendor, os_guess, [int(p) for p in open_ports_list])

        final_vendor = vendor
        if banner_info:
            final_vendor += f" ({banner_info})"

        return {
            "IP": str(ip),
            "Icon": icon_type,
            "Hostname": hostname,
            "MAC": mac or "?",
            "Vendor": final_vendor,
            "OS": os_guess,
            "Ports": ports_str
        }

    def save_to_file(self, results, filename):
        if filename.endswith(".json"):
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=4, ensure_ascii=False)
        elif filename.endswith(".csv"):
            with open(filename, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(["Type", "IP", "Hostname", "MAC", "Vendor", "OS", "Ports"])
                for r in results:
                    writer.writerow([r["Icon"], r["IP"], r["Hostname"], r["MAC"], r["Vendor"], r["OS"], r["Ports"]])
        print(Fore.GREEN + f"[+] Đã lưu kết quả vào: {filename}")

    def run(self):
        self.banner()
        parser = argparse.ArgumentParser()
        parser.add_argument("-t", "--target", help="IP Target (e.g. 192.168.1.0/24)")
        parser.add_argument("-o", "--output", help="Xuất file (e.g. result.json hoặc scan.csv)")
        parser.add_argument("--thread", type=int, default=100)
        args = parser.parse_args()

        if args.target:
            target_net = args.target
        else:
            local_ip = self.get_local_ip()
            target_net = ".".join(local_ip.split('.')[:-1]) + ".0/24"
            print(Fore.YELLOW + f"[*] IP Local: {local_ip}")
        
        print(Fore.GREEN + f"[*] Target: {target_net} | Threads: {args.thread}")
        print("-" * 60)

        try:
            network = ipaddress.ip_network(target_net, strict=False)
        except ValueError:
            print(Fore.RED + "Invalid Network Format!")
            return

        hosts = list(network.hosts())
        results = []
        
        start_time = time.time()
        print(Fore.CYAN + "[*] Scanning... (V3.0 Smart Detection)")

        with ThreadPoolExecutor(max_workers=args.thread) as executor:
            futures = {executor.submit(self.ping_and_scan, ip, args): ip for ip in hosts}
            completed = 0
            for future in as_completed(futures):
                completed += 1
                sys.stdout.write(f"\r{Fore.YELLOW}[Progress]: {completed}/{len(hosts)} ({(completed/len(hosts))*100:.0f}%)")
                sys.stdout.flush()
                res = future.result()
                if res:
                    results.append(res)

        print(f"\n{Fore.GREEN}[*] Scan Complete!")
        
        # Sort & Display
        results.sort(key=lambda x: ipaddress.IPv4Address(x["IP"]))
        
        table_data = []
        for r in results:
            table_data.append([r["Icon"], r["IP"], r["Hostname"], r["MAC"], r["Vendor"], r["OS"], r["Ports"]])

        headers = ["Type", "IP", "Hostname", "MAC Address", "Vendor/Service", "OS Guess", "Ports"]
        print(tabulate(table_data, headers=headers, tablefmt="fancy_grid"))
        
        print(Fore.CYAN + f"\n[+] Devices Found: {len(results)}")
        print(Fore.CYAN + f"[+] Time Elapsed: {time.time() - start_time:.2f}s")

        if args.output:
            self.save_to_file(results, args.output)

if __name__ == "__main__":
    try:
        scanner = NetworkScanner()
        scanner.run()
    except KeyboardInterrupt:
        print("\n[!] User Interrupted.")