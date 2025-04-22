# DiabloNetwork

**DiabloNetwork** là công cụ quét mạng LAN đơn giản sử dụng Python, cho phép bạn phát hiện và thu thập thông tin về các thiết bị đang kết nối trong mạng của mình. Công cụ này hỗ trợ quét dải IP, lấy địa chỉ MAC, và tra cứu thông tin về nhà sản xuất thiết bị qua MAC Address.

## Tính Năng:
- Quét IP trong mạng LAN để phát hiện các thiết bị hoạt động.
- Lấy địa chỉ MAC của thiết bị và tra cứu thông tin nhà sản xuất qua API MAC Vendors.
- Hiển thị kết quả quét rõ ràng với màu sắc dễ nhìn nhờ thư viện Colorama.
- Hỗ trợ đa luồng để tăng tốc độ quét mạng.

## Cách Cài Đặt:
1. **Clone repo này:**
   ```bash
   git clone https://github.com/CHT7/DiabloNetwork.git
   ```

2. **Cài đặt các phụ thuộc:**
   Trong thư mục dự án, chạy:
   ```bash
   pip install -r requirements.txt
   ```

3. **Chạy dự án:**
   Sau khi cài đặt xong, bạn có thể chạy công cụ quét mạng:
   ```bash
   python main.py
   ```

## Yêu Cầu:
- Python 3.x
- Các thư viện yêu cầu được liệt kê trong `requirements.txt` (requests, colorama, concurrent.futures).

## Cách Sử Dụng:
1. Sau khi chạy chương trình, bạn sẽ được yêu cầu nhấn `Enter` để bắt đầu quét.
2. Công cụ sẽ quét mạng của bạn và hiển thị thông tin về các thiết bị, bao gồm:
   - Địa chỉ IP
   - Địa chỉ MAC
   - Nhà sản xuất của thiết bị

## Lưu Ý:
- Đảm bảo rằng bạn có quyền truy cập vào mạng LAN bạn đang quét.
- Đảm bảo hệ thống không bị firewall ngăn chặn các lệnh ping.

## Tương Lai:
- Tích hợp thêm khả năng phát hiện các thiết bị ẩn hoặc bị chặn.
- Tạo giao diện đồ họa (GUI) cho công cụ.
- Cải thiện khả năng quét và phân tích các dịch vụ đang chạy trên các thiết bị.

## Giới Thiệu:
DiabloNetwork là một công cụ hữu ích dành cho các quản trị viên mạng và những ai muốn kiểm tra các thiết bị kết nối trong hệ thống mạng của mình. Công cụ này dễ sử dụng và có khả năng quét mạng nhanh chóng với thông tin chi tiết về các thiết bị.

## License:
Đây là một dự án mã nguồn mở, bạn có thể sử dụng, sửa đổi, và phân phối lại mã nguồn theo giấy phép **MIT License**.
