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
- **Wildcard.** `*.example.com` cho phép mọi *tên* dưới example.com (không gồm example.com).
  `reconkit scan example.com --discover` dùng subfinder tìm subdomain (thụ động, không gửi gì
  tới mục tiêu), rồi chỉ quét những tên có mọi địa chỉ nằm trong scope; tên bị loại được ghi
  lại kèm lý do. Cần cài `subfinder` (ProjectDiscovery).
- **IPv6 cũng vậy.** Tên được phân giải ra cả IPv4 và IPv6; địa chỉ IPv6 cũng phải có trong
  scope (vd `2001:db8::/64`), hoặc quét `--ipv4-only`. Không quét quét dải IPv6 lớn hơn /112.
- **Deny thắng allow.** Quét một dải có chứa địa chỉ bị cấm thì địa chỉ đó được loại trừ
  (`nmap --exclude`); target bị cấm toàn bộ thì bị từ chối.
- **Kết quả được kiểm lại.** Máy nào scanner trả về mà nằm ngoài scope sẽ không được lưu và
  CLI in cảnh báo.

### Theo dõi qua nhiều lần quét

Mỗi lần quét được đối chiếu với **kho tài sản** (mọi host, cổng, lỗi đã từng thấy). Sau khi quét,
CLI in ra những gì thay đổi, và cảnh báo khi một lỗi đã báo sửa vẫn còn (**fix giả**) hoặc lỗi cũ
quay lại:

```bash
reconkit findings                     # lỗi còn mở, theo thứ tự ưu tiên
reconkit finding 12                   # chi tiết + lịch sử của một lỗi
reconkit finding 12 --claim-fixed     # báo đã sửa: lần quét sau sẽ xác minh (hoặc báo fix giả)
reconkit finding 7 --accept --reason "máy cô lập, thay trong Q1" --until 2027-03-31
reconkit inventory                    # mọi host / cổng đã thấy, thấy lần đầu / cuối khi nào
reconkit diff                         # run mới nhất so với run trước đó cùng target
reconkit diff 3 8                     # hai run bất kỳ (có cảnh báo nếu không so sánh được)
```

"Không thấy" chưa chắc là "đã vá": ReconKit chỉ kết luận một lỗi đã hết khi host vẫn trả lời,
cổng đó chắc chắn đã được quét và dữ liệu CVE cùng loại — xem `docs/THIET-KE.md`.

### Giấy phép quét & audit trail

File scope có thể ghi điều khoản của giấy phép, ReconKit sẽ tuân theo:

```text
@engagement PT-2026-014, ký 2026-11-01 với ACME IT   # ghi vào mỗi run
@expires 2026-12-31 +07:00                           # sau ngày này: từ chối quét
@window Mon-Fri 22:00-06:00 +07:00                   # chỉ quét trong khung giờ này
10.0.0.0/24
```

Mỗi run lưu người chạy (`--operator`, mặc định `user@máy`), engagement, đường dẫn + SHA-256 của
file scope (và nội dung của nó), cùng danh sách địa chỉ đã được duyệt. Mọi lần quét, mọi lần bị
từ chối và mọi lần xóa run được ghi vào **audit trail dạng chuỗi băm**:

```bash
reconkit audit --db reconkit.db            # ai quét gì, lúc nào, theo giấy phép nào
reconkit audit --db reconkit.db --verify   # kiểm chuỗi băm + bằng chứng; in mã băm đầu chuỗi
reconkit audit --db reconkit.db --scope 21e2cba7   # nội dung file scope đã dùng
reconkit delete 3 --db reconkit.db --yes   # xóa một run (việc xóa cũng được ghi lại)
```

Lưu mã băm đầu chuỗi ở nơi khác (ticket, email gửi khách hàng): so lại là biết lịch sử có bị
viết lại hay không.

Cần cài `nmap` trên PATH. Mỗi lần quét được lưu thành một *run* có trạng thái: `completed`,
`partial` (thiếu scanner) hoặc `failed` (kèm lỗi, không có kết quả). Một run `completed` với
0 service nghĩa là "đã quét và không thấy gì", không bao giờ là "chưa quét". Run còn ghi
phiên bản của từng scanner đã chạy.

Database có số phiên bản schema. Mở một DB cũ thì ReconKit tự nâng cấp, sau khi sao lưu
bản cũ ra `<db>.v<N>.bak`; DB do bản ReconKit mới hơn tạo ra thì từ chối mở.

CVE được khớp theo CPE và **dải phiên bản** (dữ liệu kiểu NVD), sau khi tách version nmap
báo về (`7.4p1 Debian 10+deb9u7` → bản upstream 7.4). Mỗi lỗi có **độ tin cậy**: `tentative`
khi dịch vụ là gói của một distro (có thể đã được vá bằng backport mà không đổi số version),
`firm` khi version upstream rõ ràng, `confirmed` chỉ khi có bài kiểm chạm vào lỗi thật.
`--cve-db file.json` dùng file dữ liệu CVE khác seed đi kèm (định dạng như
`reconkit/data/cve_seed.json`).

### Dữ liệu CVE thật: cache NVD

Seed đi kèm chỉ có vài CVE để chạy thử. Dữ liệu thật lấy từ NVD về một cache ở máy:

```bash
export NVD_API_KEY=...        # không bắt buộc; có key thì tải nhanh gấp 10 lần
reconkit cve sync                                        # lần đầu: cả NVD (lâu)
reconkit cve sync --product cpe:2.3:a:openbsd:openssh    # hoặc chỉ vài sản phẩm
reconkit cve status                                      # cache có gì, sync lúc nào
reconkit cve show CVE-2024-6387
reconkit scan 10.0.0.5 --scope scope.txt --cve-cache reconkit-cve.db
```

Các lần `sync` sau chỉ tải những CVE NVD đã sửa từ lần trước. `sync` cũng tải catalog **CISA
KEV** (lỗi đang bị khai thác thật) và điểm **EPSS** (xác suất bị khai thác trong 30 ngày).

Mỗi lỗi được xếp **ưu tiên**:

| | Khi nào | Ý nghĩa |
|---|---|---|
| P1 | có trong CISA KEV | đang bị khai thác ngoài thực tế: xử lý ngay |
| P2 | EPSS ≥ 10 % hoặc CVSS ≥ 9.0 | nhiều khả năng bị khai thác / tác động rất nặng |
| P3 | EPSS ≥ 1 % hoặc CVSS ≥ 7.0 | |
| P4 | còn lại | |

Lý do: phần lớn CVE "critical" không bao giờ bị khai thác, trong khi vài lỗi "medium" bị khai
thác hằng ngày; nên xét bằng chứng khai thác trước, mức tác động sau. Lúc quét, việc khớp CVE chạy
hoàn toàn trên cache: không có thông tin nào về mục tiêu bị gửi ra ngoài.

Output gốc của scanner (XML của nmap) được giữ lại theo từng run làm bằng chứng, kèm mã băm
SHA-256, kể cả khi lần quét thất bại. Lấy lại bằng:

```bash
reconkit raw 1 --db reconkit.db                 # in ra màn hình (pipe được)
reconkit raw 1 --db reconkit.db --out run1.xml  # ghi ra file
```

## Log

`-v` (tiến trình) / `-vv` (chi tiết) in log ra stderr; `--log-file scan.log` ghi log đầy đủ;
`--log-format json` cho hệ thống gom log. Ví dụ: `reconkit scan 10.0.0.5 --scope scope.txt -v`.

## Báo cáo & bản đồ bề mặt tấn công

```bash
reconkit runs --db reconkit.db                          # danh sách các run, mới nhất trước
reconkit report --db reconkit.db --html report.html     # báo cáo run mới nhất
reconkit report --db reconkit.db --run 3 --html run3.html
reconkit report --db reconkit.db --json run.json --sarif run.sarif   # dữ liệu / SARIF 2.1.0
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
| 3 | Từ chối (và được ghi vào audit trail): target nằm ngoài scope, tên miền trỏ tới IP ngoài scope, target bị denylist phủ kín, giấy phép đã hết hạn hoặc ngoài khung giờ cho phép |
| 4 | Quét thất bại, lưu thành run `failed` **không có kết quả**: thiếu nmap, nmap lỗi / quá thời gian, không phân giải được tên, không host nào trả lời |
