# ReconKit

Bộ điều phối recon & quản lý lỗ hổng chạy nền (đồ án an toàn thông tin).

> ⚠️ Chỉ dùng trên tài sản của mình hoặc được uỷ quyền bằng văn bản (lab, mạng nội bộ, chương trình có scope hợp pháp).

## Tài liệu thiết kế (SDD v0.1)
https://claude.ai/artifact/69X8tKYCnShu8rYwzaNiV8

## Trạng thái
- [x] Tài liệu thiết kế
- [x] Chốt ngôn ngữ: **Python** (zero-dependency core — chỉ dùng thư viện chuẩn)
- [x] Lát cắt dọc: schema + scope + plugin nmap + orchestrator + storage + CLI

Lộ trình chi tiết: [`TASKS.md`](TASKS.md).

## Cài đặt (dev)

```bash
python -m venv .venv
.venv/Scripts/activate        # Windows; macOS/Linux: source .venv/bin/activate
pip install -e ".[dev]"
pytest
```

## Dùng thử

```bash
# scope.txt: allowlist, mỗi dòng một target (host / IP / CIDR, '!' = deny, '#' = chú thích)
printf 'scanme.lab\n10.0.0.0/24\n!10.0.0.1  # router, khong duoc quet\n' > scope.txt

reconkit scan scanme.lab --scope scope.txt --db reconkit.db
reconkit scan 10.0.0.0/24 --scope scope.txt        # quét cả dải, tự loại trừ 10.0.0.1
reconkit scan 10.0.0.0/24 --scope scope.txt --traceroute   # ghi cả đường đi tới từng host (profile full bật sẵn)
```

### Scan profile

```bash
reconkit profiles                                   # liệt kê profile + tuỳ chọn nmap tương ứng
reconkit scan 10.0.0.0/24 --scope scope.txt --profile full           # cả 65.535 cổng + traceroute
reconkit scan 10.0.0.5 --scope scope.txt --profile quick --timing 3   # ghi đè một thông số
reconkit scan 10.0.0.5 --scope scope.txt --ports 22,80,8000-8100
reconkit scan 10.0.0.0/24 --scope scope.txt --config reconkit.toml --profile nightly
```

| Profile | Quét gì | Dùng khi |
|---|---|---|
| `quick` | 100 cổng phổ biến, `-T4`, timeout 5 phút | xem nhanh |
| `standard` (mặc định) | 1.000 cổng phổ biến, `-T4`, timeout 15 phút | quét thường |
| `full` | cả 65.535 cổng TCP + traceroute, timeout 4 giờ | quét định kỳ |
| `gentle` | 1.000 cổng, `-T2`, tối đa 50 gói/giây | mạng yếu / thiết bị dễ treo |

File cấu hình (TOML) thêm profile mới dựa trên một profile dựng sẵn:

```toml
[profiles.nightly]
base = "full"
timing = 3
max_rate = 300        # gói/giây
host_timeout = 1800   # bỏ một host sau 30 phút
```

Mỗi run lưu tên profile và toàn bộ thông số: hai run khác profile thì không nhìn cùng một tập
cổng, nên không so sánh được với nhau.

`--traceroute` ghi lại các router nằm giữa máy quét và từng host (dùng để vẽ bản đồ). Probe
chỉ gửi tới host trong scope; router trên đường đi chỉ trả lời "TTL hết hạn", không bị quét.
nmap cần quyền raw socket (root trên Linux, Npcap trên Windows); target nằm ngay trên máy
quét thì không có route.

Quy tắc của scope:

- **Tên miền trong allowlist chưa đủ.** ReconKit phân giải tên một lần, và *mọi* IP nó trỏ
  tới cũng phải nằm trong allowlist; nếu không sẽ từ chối và nêu rõ IP nào. Vì vậy file
  scope phải khai cả IP / dải của máy, không chỉ tên. nmap luôn được đưa **IP** đã kiểm tra,
  không bao giờ là tên.
- **Deny thắng allow.** Quét một dải có chứa địa chỉ bị cấm thì địa chỉ đó được loại trừ
  (`nmap --exclude`); target bị cấm toàn bộ thì bị từ chối.
- **Kết quả được kiểm lại.** Máy nào scanner trả về mà nằm ngoài scope sẽ không được lưu và
  CLI in cảnh báo.

Cần cài `nmap` trên PATH. Mỗi lần quét được lưu thành một *run* có trạng thái: `completed`,
`partial` (thiếu scanner) hoặc `failed` (kèm lỗi, không có kết quả). Một run `completed` với
0 service nghĩa là "đã quét và không thấy gì", không bao giờ là "chưa quét". Run còn ghi
phiên bản của từng scanner đã chạy.

Database có số phiên bản schema. Mở một DB cũ thì ReconKit tự nâng cấp, sau khi sao lưu
bản cũ ra `<db>.v<N>.bak`; DB do bản ReconKit mới hơn tạo ra thì từ chối mở.

Output gốc của scanner (XML của nmap) được giữ lại theo từng run làm bằng chứng, kèm mã băm
SHA-256, kể cả khi lần quét thất bại. Lấy lại bằng:

```bash
reconkit raw 1 --db reconkit.db                 # in ra màn hình (pipe được)
reconkit raw 1 --db reconkit.db --out run1.xml  # ghi ra file
```

## Báo cáo & bản đồ bề mặt tấn công

```bash
reconkit runs --db reconkit.db                          # danh sách các run, mới nhất trước
reconkit report --db reconkit.db --html report.html     # báo cáo run mới nhất
reconkit report --db reconkit.db --run 3 --html run3.html
```

`report.html` là **một file duy nhất, mở offline** (không tải gì từ mạng): bản đồ
máy quét → router → dải mạng ⊃ host ⊃ cổng → lỗ hổng, kèm bảng finding (theo mức độ, có bằng
chứng), bảng host và thông tin run. Bấm vào một node hoặc một dòng bảng để xem chi tiết. Đường
nét đứt = có router không trả lời traceroute; chấm chấm = host chưa được traceroute.

Dữ liệu trong báo cáo do chính máy bị quét khai ra (banner…), nên được coi là không tin cậy:
nó chỉ được hiển thị dưới dạng chữ, và Content-Security-Policy của trang chỉ cho chạy đúng các
đoạn script đã biết mã băm, cấm mọi kết nối mạng.

> File DB chứa toàn bộ kết quả và output gốc của các lần quét: coi nó là dữ liệu nhạy cảm của
> đợt kiểm thử, không chia sẻ và không commit. Báo cáo HTML cũng vậy.

| Exit code | Ý nghĩa |
|---|---|
| 0 | Quét xong, kết quả đã lưu vào DB |
| 1 | Không dùng được database (hỏng, không phải SQLite, hoặc schema mới hơn bản ReconKit này) — chưa quét gì |
| 2 | Đầu vào sai: không thấy file scope / file cấu hình, có dòng không hợp lệ, profile hoặc thông số quét sai |
| 3 | Từ chối: target nằm ngoài scope, tên miền trỏ tới IP ngoài scope, hoặc target bị denylist phủ kín |
| 4 | Quét thất bại, lưu thành run `failed` **không có kết quả**: thiếu nmap, nmap lỗi / quá thời gian, không phân giải được tên, không host nào trả lời |
