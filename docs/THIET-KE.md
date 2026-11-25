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
| D17 | Giới hạn quét (2026-11-25) | **Một target chỉ một lần quét đang chờ hoặc đang chạy, với mọi nguồn (dashboard, MCP, `zues enqueue`, scheduler), kiểm dưới một khoá ngắn trên Redis; mỗi token có thể có `scans_per_hour`: cửa sổ trượt một giờ trong Redis (sorted set, WATCH), quá thì 429 + `Retry-After`; yêu cầu trùng không tính, scheduler không tính** | Agent và script dùng token, nên giới hạn theo token chứ không theo IP; cửa sổ trượt không cho gấp đôi ở ranh giới giờ như cửa sổ cố định; Redis là chỗ chung của mọi tiến trình web; lượt lịch trùng thì bỏ (như `flock` / cron no-overlap) thay vì xếp chồng sau một lần quét dài hơn chu kỳ. Tải của từng lần quét vẫn do profile quyết định |
| D18 | Kênh ngoài của nuclei (2026-11-25) | **Chỉ máy chủ interactsh tự dựng (`ZUES_INTERACTSH_SERVER`, theo tên miền; máy chủ công cộng và IP bị từ chối); token qua file cấu hình của từng lần chạy, không qua dòng lệnh hay context của plugin; hỏi máy chủ một lần trước khi quét, không được thì `-ni` + ghi chú; không có callback là "không có callback", không phải "không lỗi"** | Máy chủ công cộng làm mục tiêu tự khai ra ngoài cuộc kiểm thử; dòng lệnh thì mọi người dùng trên máy thấy và được lưu làm bằng chứng; nuclei im lặng chạy tiếp khi client interactsh hỏng, nên phải tự kiểm; máy quét không biết mục tiêu có tới được máy chủ không |
| D19 | Hàng đợi không phải đường chạy code (2026-11-25) | **Job RQ là JSON, worker chỉ chạy job quét của ZuesScan (và callback lỗi của nó), job khác failed không chạy; Redis có mật khẩu, đọc từ file (`redis_password_file` / `ZUES_REDIS_PASSWORD_FILE`), compose tự sinh trong volume `secrets`** | Pickle của RQ biến quyền ghi Redis thành quyền chạy code trong worker — plugin bên thứ ba ở cùng mạng đã làm được (thử thật); file thay vì biến môi trường vì tiến trình plugin không nhận biến `ZUES_*` và Landlock không cho đọc `/secrets`; hai lớp vì mật khẩu có thể lộ, còn danh sách job thì không đổi được từ Redis |
| D16 | Giới hạn file của plugin bên thứ ba (2026-11-24) | **Landlock trong tiến trình con, trước khi import: đọc hệ thống + Python + gói của ZuesScan / plugin + công cụ + templates, ghi thư mục tạm; danh sách do tiến trình cha tính; kernel có Landlock mà giới hạn hỏng → lời gọi hỏng; không có Landlock → chạy và doctor cảnh báo** | Không cần root hay container riêng (worker chạy uid 10001), có sẵn trong kernel 5.13+ và seccomp mặc định của Docker; danh sách cho phép (không phải danh sách cấm) nên thư mục mới của dịch vụ tự nằm ngoài; ptrace bị chặn kèm theo. Mạng để sau (Landlock chỉ lọc theo cổng) |
| D15 | Plugin bên thứ ba chạy ở đâu (2026-11-24) | **Mỗi lời gọi một tiến trình con (`python -I -m zues_scan.plugins.process`), JSON qua stdin / stdout, môi trường sạch, thư mục tạm, giết cả nhóm khi hết giờ; kể cả đọc spec; tiến trình con kiểm lại pin; trả lời được kiểm theo kiểu của schema** | Tiến trình con mỗi lời gọi đơn giản và chắc hơn một tiến trình sống lâu (không cần khung tin nhắn, mỗi lời gọi có hạn giờ riêng, không rò trạng thái); chi phí khởi động nhỏ so với một lần quét; plugin dựng sẵn vẫn chạy trong tiến trình (là code của ZuesScan, chúng đã chạy công cụ ở tiến trình con). Giới hạn file: D16 |
| D14 | Plugin bên thứ ba trong dịch vụ (2026-11-24) | **Dịch vụ chỉ nạp plugin được ghim (`[[plugins]]` / `ZUES_PLUGINS`): gói + phiên bản + SHA-256 các file trong RECORD, kiểm trước khi import; `activity` cho cổng scope là mức người vận hành ghi (plugin khai cao hơn → bị từ chối); không ghim → chỉ plugin dựng sẵn; dòng lệnh của người dùng vẫn nạp mọi plugin đã cài** | Code của plugin chạy ngay khi import, nên quyết định phải xảy ra trước đó, chỉ từ file trên đĩa; cách làm giống `pip --require-hashes` và `tools.lock`; người vận hành chịu trách nhiệm về mức chủ động, không phải tác giả plugin. Bước tiếp theo: D15 |
| D13 | Quyền theo target (2026-11-24) | **Token viewer / operator có `targets` (mẫu tên, `acme-*`); run ghi `target_name`; finding / host thấy được = host mà run của target được phép tìm thấy; ngoài phạm vi → 404; audit chỉ cho token không giới hạn; admin không giới hạn** | Nhiều khách hàng trên một dịch vụ mà không lộ tên / dữ liệu của nhau; mẫu tên đủ cho cách đặt tên theo khách hàng, không cần thêm khái niệm "tenant"; 404 thay vì 403 để không xác nhận sự tồn tại |
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
