# Thiết kế & quyết định — ZuesScan

Bản tóm tắt của tài liệu "Phân tích & Thiết kế hệ thống v0.2" (bản Word lưu ngoài git).
Các quyết định dưới đây được chốt ngày **2026-11-07**; muốn đổi thì sửa file này trong một PR
và ghi lý do.

Liên quan: [`TASKS.md`](../TASKS.md) (lộ trình) · [`KNOWN-GAPS.md`](KNOWN-GAPS.md) (điểm yếu G1–G20)

## Đích đến

Từ một công cụ CLI quét một mục tiêu, ZuesScan trở thành **dịch vụ chạy nền**:

- quét định kỳ các mạng đã được uỷ quyền;
- **ghi nhớ** kết quả theo thời gian;
- phát hiện thay đổi: máy mới, cổng mới, lỗi mới, lỗi đã vá, **fix giả**;
- gửi cảnh báo;
- hiển thị **bản đồ bề mặt tấn công** trên web.

Lõi hiện tại (orchestrator + plugin + schema + storage) **không bị viết lại**. Nó trở thành
phần *worker*, các lớp mới chỉ bọc bên ngoài.

Bản đồ **không phải sơ đồ đi dây**. Nó là đồ thị quan hệ suy ra từ dữ liệu quét:

```
máy quét → hop (traceroute) → dải mạng → host → cổng/dịch vụ → lỗ hổng
                                           ↑
                               tên miền (phân giải DNS)
```

Vì thế bản đồ không hiện được những thứ máy quét không thấy, ví dụ switch lớp 2 hay đoạn
mạng bị firewall chặn.

## Nguyên tắc: dữ liệu đúng trước, giao diện sau

Với dữ liệu hiện tại thì chưa vẽ được bản đồ:

- quét một dải IP thì mọi máy bị gộp thành một asset (G1);
- finding đọc lại từ DB không biết thuộc cổng nào (G5);
- fingerprint có chứa `title`, nên chỉ cần sửa câu chữ là thành "lỗi mới" (G12).

Các nhánh F5, F7, F8 của Giai đoạn 1.5 chính là bước **tạo ra dữ liệu cho bản đồ**. Vì vậy
cột mốc M1 (giao diện đầu tiên) chỉ bắt đầu sau F9.

## Các quyết định đã chốt

| # | Câu hỏi | Chọn | Lý do |
|---|---|---|---|
| D1 | Mô hình dữ liệu | **Lai**: kho tài sản (`host`, `service`, `finding` có `first_seen` / `last_seen` / `status`) + lịch sử từng run (`observation`, `route_hop`, `evidence`, `finding_event`). Làm cùng `feat/diff` ở GĐ 2. | Có cả hiện trạng lẫn lịch sử, nên trả lời được "lỗi này mở bao lâu", "lần quét nào thấy gì". Không làm phình F7. |
| D2 | Giao diện đầu tiên | **Báo cáo HTML tĩnh** (M1), một file, mở offline | Thấy kết quả sớm, chưa phải dựng server và đăng nhập |
| D3 | Thư viện vẽ đồ thị | **Cytoscape.js** | *Compound node* (host nằm trong dải mạng) khớp đúng mô hình; dùng lại được ở web app |
| D4 | Web framework (GĐ 3) | **FastAPI** | Python có type hint như lõi; tự sinh tài liệu API |
| D5 | Frontend web app | **JavaScript thuần, không build** (chốt 2026-11-23, sau M1) | M1 cho thấy phần tương tác nặng nhất (bản đồ) đã có sẵn trong báo cáo HTML; dashboard chỉ cần bảng + form. Không npm / bundler = không chuỗi cung ứng phụ thuộc, CSP chặt được (`script-src 'self'`); htmx hay React đều thêm thư viện mà không thêm gì cần thiết |
| D6 | Hàng đợi (GĐ 3) | **Redis + RQ** | Đơn giản, đủ cho vài worker |
| D7 | Traceroute | **Có**, plugin nmap bật `--traceroute` theo profile | Cần cho các hop trên bản đồ; đổi lại quét lâu hơn một chút |
| D8 | Lộ trình | **Chèn M1 sau F9** | Xem `TASKS.md` |
| D12 | Hai người cho thay đổi scope (2026-11-24) | **Tuỳ chọn phía server `scope_approval`: sửa / xoá scope trên dashboard thành đề xuất; admin khác duyệt (cùng transaction với audit); không duyệt bằng token mà người đề xuất đã thấy giá trị (chuỗi `created_by` / `rotated_by`)** | Scope là giấy phép quét: một admin không tự mở rộng được; mặc định tắt để cài một admin vẫn dùng được; dashboard không tắt được nó; chặn cách lách "tự tạo admin thứ hai" mà vẫn cho quy trình thật (người nhận tự Rotate) |
| D11 | Cấu hình qua dashboard (2026-11-23) | **Scope / target / token sửa trên dashboard nằm trong database (schema 14), `service.toml` chỉ đọc và thắng khi trùng tên; vai trò `admin`; kiểm như lúc quét trước khi lưu; mọi thay đổi vào chuỗi audit** | Cài đặt không cần sửa file tay; người chạy máy chủ vẫn giữ quyền cuối (file); một mục dashboard hỏng không làm sập dịch vụ (bị bỏ + báo); admin mở rộng được scope theo yêu cầu chủ dự án — bù lại bằng audit có chuỗi băm (G30) |
| D10 | AI agent (2026-11-23) | **MCP server stdio là client của web API; mỗi hành động cần người xác nhận (elicitation qua `Resolve`); không có tool chấp nhận rủi ro** | Một mô hình quyền duy nhất (token, vai trò, audit) cho người và AI; model không tự điền được câu trả lời xác nhận; quyết định có trách nhiệm pháp lý để lại cho con người |
| D9 | Mở rộng công cụ (2026-11-23) | **Registry + entry points `zues_scan.plugins`; mỗi plugin khai `activity`, scope đặt trần `@activity` (mặc định `scan`)** | Thêm công cụ = cài một gói, không sửa lõi; được khai thác hay không thuộc về giấy phép, không thuộc về cờ dòng lệnh. Xem `docs/PLUGINS.md` |

Ràng buộc chung: lõi vẫn **không phụ thuộc thư viện ngoài**. Thư viện web và hàng đợi đặt
trong gói tuỳ chọn `zues-scan[server]`.

## Vòng đời một lỗ hổng (dựa trên fingerprint) — ✅ đã làm (`feat/diff`)

```
MỚI → ĐANG MỞ → ĐÃ BÁO SỬA → (run sau không thấy) → ĐÃ XÁC MINH VÁ → (thấy lại) → TÁI XUẤT HIỆN
                     │
                     └→ (run sau vẫn thấy) → FIX GIẢ  ⚠ cảnh báo mức cao nhất
ĐANG MỞ → (tự hết, chưa ai báo sửa) → BIẾN MẤT  (cần kiểm tra: đã vá hay máy đang tắt?)
ĐANG MỞ → CHẤP NHẬN RỦI RO  (phải có lý do + hạn xem lại)
```

"Không thấy" chưa chắc là "đã vá". Chỉ xác nhận đã vá khi host vẫn phản hồi mà lỗi không còn.

Cách ZuesScan áp dụng quy tắc trên (`zues_scan/inventory.py`): một run chỉ được coi là "đã nhìn
vào" một lỗi khi (1) host trả lời, (2) cổng chắc chắn được quét — dịch vụ vẫn mở, hoặc cùng
profile với lần thấy lỗi, hoặc profile liệt kê rõ cổng đó, và (3) với CVE: cùng loại dữ liệu CVE
(seed / cache NVD). Run không nhìn vào thì **không đổi gì**. Host nằm trong kế hoạch quét mà
không trả lời → `not_responding`, không phải "đã vá".

| Trạng thái (code) | Nghĩa |
|---|---|
| `new` → `open` | thấy lần đầu → thấy lại |
| `fix_claimed` | có người báo đã sửa (`zues finding ID --claim-fixed`) |
| `fixed` | đã báo sửa và run sau (có nhìn vào) không còn thấy |
| `fake_fix` ⚠ | đã báo sửa nhưng run sau vẫn thấy |
| `gone` | tự hết mà chưa ai báo sửa: kiểm tra lại |
| `reappeared` ⚠ | đã `fixed` / `gone` rồi lại thấy |
| `accepted` | chấp nhận rủi ro, bắt buộc có lý do + hạn xem lại; quá hạn → `open` |

Quyết định của con người (báo sửa, chấp nhận, mở lại) được ghi cả vào chuỗi audit (G21).
