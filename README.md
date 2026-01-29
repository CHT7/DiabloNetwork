# ⚡ DiabloNetwork V3.0 - THE GOD MODE NETWORK SCANNER ⚡

**DiabloNetwork** là một công cụ quét mạng LAN mạnh mẽ, nhanh chóng và thông minh được viết bằng Python. Phiên bản V3.0 "God Mode" mang đến khả năng nhận diện thiết bị chuyên sâu, quét cổng dịch vụ và dự đoán hệ điều hành với độ chính xác cao, hỗ trợ hoàn hảo trên Windows, Linux và đặc biệt là **Termux**.

![DiabloNetwork V3.0 Preview](https://img.shields.io/badge/Version-3.0_God_Mode-red?style=for-the-badge)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20Termux-blue?style=for-the-badge)

## 🔥 Tính Năng Đột Phá:
- 🚀 **Multi-threaded Scanning:** Sử dụng ThreadPoolExecutor để quét hàng trăm IP chỉ trong vài giây.
- 🛠️ **Smart OS Detection:** Kết hợp chỉ số TTL và trạng thái cổng mở để đoán hệ điều hành (Windows, Linux, iOS, Android, Cisco...).
- 📱 **Device Fingerprinting:** Tự động phân loại thiết bị bằng Icon trực quan (Laptop 💻, Mobile 📱, Camera 📷, Router 🌐).
- 🔍 **Port Scan & Banner Grabbing:** Quét các cổng phổ biến (80, 443, 22, 554...) và "hút" thông tin server header (ví dụ: Apache, Hikvision Web Server).
- 📋 **Local Vendor DB & API:** Tra cứu nhà sản xuất cực nhanh qua database nội bộ kết hợp API MacVendors.
- 💾 **Export Data:** Hỗ trợ xuất kết quả quét ra định dạng `JSON` hoặc `CSV` để làm báo cáo.
- 🖥️ **Adaptive Interface:** Giao diện tự làm sạch, thanh tiến trình hiện đại và tự thích nghi với màn hình nhỏ (Termux).

## 🛠️ Yêu Cầu Hệ Thống:
DiabloNetwork yêu cầu Python 3.x và một số thư viện sau:
```bash
pip install requests colorama tabulate

```

## 🚀 Cách Sử Dụng:

### 1. Quét mạng mặc định (Tự động nhận diện dải IP):

```bash
python main.py

```

### 2. Quét dải IP cụ thể:

```bash
python main.py -t 192.168.1.0/24

```

### 3. Tùy chỉnh số luồng (Tăng tốc độ):

```bash
python main.py --thread 200

```

### 4. Xuất báo cáo ra file:

```bash
python main.py -o result.csv
# Hoặc
python main.py -o scan_data.json

```

## 📸 Giao diện:

Tool sở hữu giao diện bảng chuyên nghiệp, hỗ trợ đầy đủ các cột thông tin:
`Type | IP | Hostname | MAC Address | Vendor/Service | OS Guess | Ports`

## ⚠️ Lưu Ý:

* Đảm bảo bạn có quyền truy cập hợp pháp vào mạng đang quét.
* Một số Firewall có thể chặn gói tin Ping, dẫn đến việc không phát hiện được thiết bị.

## 📄 License:

Phát hành dưới giấy phép **MIT License**. Tự do sử dụng và phát triển bởi cộng đồng.

---

Developed with ❤️ by **CHT7**

