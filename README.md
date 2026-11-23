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
pip install -e ".[dev,server,server-test]"   # thêm test của dịch vụ chạy nền (Redis giả trong RAM)
```

## Dùng thử

```bash
# scope.txt: allowlist, mỗi dòng một target (host / IP / CIDR, '!' = deny, '#' = chú thích)
printf 'scanme.lab\n10.0.0.0/24\n!10.0.0.1  # router, khong duoc quet\n' > scope.txt

reconkit scan scanme.lab --scope scope.txt --db reconkit.db
reconkit scan 10.0.0.0/24 --scope scope.txt        # quét cả dải, tự loại trừ 10.0.0.1
reconkit scan 10.0.0.0/24 --scope scope.txt --traceroute   # ghi cả đường đi tới từng host (profile full bật sẵn)
```

### Kiểm tra web bằng nuclei (chủ động)

`--nuclei` chạy template nuclei trên các dịch vụ HTTP(S) mà nmap tìm được. Đây là kiểm tra
**chủ động** (gửi request khai thác an toàn), chỉ dùng khi giấy phép cho phép. Mặc định: không
dùng interactsh (không để mục tiêu gọi ra máy chủ công cộng), bỏ các template `dos`, `fuzz`,
`intrusive`, `bruteforce`, giới hạn số request/giây theo profile. URL luôn dùng địa chỉ đã
duyệt; tên miền (vhost) được gửi qua Host header + SNI. Cần cài `nuclei`.

### Quét có đăng nhập (Debian)

```toml
# creds.toml — chỉ SSH key, không nhận mật khẩu
[[ssh]]
hosts = ["10.0.0.0/24"]
user = "audit"                                 # tài khoản thường, không cần sudo
key = "~/.ssh/reconkit_audit"
known_hosts = "~/.ssh/reconkit_known_hosts"    # host key phải có sẵn ở đây
```

```bash
reconkit cve sync --debian bookworm      # tải Debian Security Tracker (~90 MB)
reconkit scan 10.0.0.0/24 --scope scope.txt --cve-cache reconkit-cve.db --credentials creds.toml
```

ReconKit đọc gói đã cài và báo những CVE mà bản vá chưa được cài — chính xác hơn đoán theo
banner, vì Debian vá bằng backport mà không đổi số version của phần mềm. Ngược lại, CVE nào gói
đã có bản vá thì các finding đoán theo banner cho CVE đó bị rút lại.

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

## Chạy nền: lịch quét, hàng đợi, worker

Phần dịch vụ nằm trong gói tuỳ chọn (lõi quét vẫn không phụ thuộc thư viện ngoài):

```bash
pip install -e ".[server]"        # Redis + RQ (+ FastAPI cho web API ở bước sau)
```

Mọi thứ dịch vụ được làm đều khai trong **một file `service.toml`**, và đây là luật quan trọng
nhất: **chỉ target có tên trong file này mới quét được** — dù do lịch quét hay do người yêu cầu.
Một yêu cầu quét chỉ mang *tên* target; nó không mang địa chỉ, file scope hay tuỳ chọn nào, nên
dịch vụ không thể bị biến thành "máy quét hộ" cho bất kỳ địa chỉ nào.

```toml
[service]
db = "/data/reconkit.db"
cve_cache = "/data/reconkit-cve.db"     # tuỳ chọn: dữ liệu NVD cho bước CVE
redis_url = "redis://localhost:6379/0"
queue = "reconkit"

[[tokens]]                              # ai được dùng API (web, bước sau)
name = "alice"
sha256 = "…"                            # mã băm của token, KHÔNG BAO GIỜ lưu token
role = "operator"                       # viewer: chỉ xem; operator: quét, ra quyết định

[[targets]]
name = "office-lan"
target = "10.0.0.0/24"
scope = "/config/scope-office.txt"      # vẫn qua scope guard như lệnh scan
profile = "full"
every = "24h"                           # tuỳ chọn: quét định kỳ (m / h / d, tối thiểu 5m)
engagement = "PT-2026-014"

[notify]
webhook = "https://hooks.slack.com/services/…"   # tuỳ chọn, payload kiểu Slack {"text": …}
min_priority = "P2"                              # báo finding mới từ mức này trở lên
```

```bash
reconkit token --name alice --role operator     # in token MỘT lần + dòng [[tokens]] để dán vào file
docker run -d -p 6379:6379 redis:7.4-alpine     # Redis cho hàng đợi
reconkit worker --config service.toml           # chạy các lần quét trong hàng đợi (chạy nhiều worker được)
reconkit scheduler --config service.toml        # mỗi phút xếp hàng các target đến hạn
reconkit enqueue office-lan --config service.toml --operator alice   # quét ngay một target
reconkit scheduler --config service.toml --once                      # một vòng rồi dừng (cron)
```

- **Worker** chạy đúng `scanning.execute` mà lệnh `scan` dùng: cùng scope guard, cùng audit
  trail, cùng cách lưu run (kể cả run `failed`). Job chỉ chứa *tên* target; worker đọc lại
  `service.toml` lúc chạy, nên target bị gỡ khỏi file sau khi đã xếp hàng sẽ **không** bị quét.
  Mỗi job có giới hạn thời gian = timeout của profile + 10 phút; kết quả job giữ 7 ngày trong
  Redis, job lỗi giữ 30 ngày — còn nguồn sự thật vẫn là database.
- Trên Linux mỗi job chạy trong một tiến trình con riêng (fork); trên Windows không có `fork()`
  và `SIGALRM`, nên worker chạy job ngay trong tiến trình của nó, giới hạn thời gian bằng luồng
  hẹn giờ (xem G23).
- **Scheduler**: một target đến hạn khi cả lần quét gần nhất (cùng target **và** cùng profile —
  quét nhanh mỗi giờ không làm lần quét đầy đủ mỗi ngày tưởng là đã xong) lẫn lần xếp hàng gần
  nhất (ghi trong Redis) đều cũ hơn `every`. Mỗi vòng giữ một khoá ngắn trong Redis, nên lỡ chạy
  hai scheduler cũng không xếp trùng một lần quét; khởi động lại scheduler cũng vậy.
- **Cảnh báo** (webhook) chỉ gửi khi bức tranh thay đổi: **fix giả** (đã báo sửa mà vẫn còn),
  finding **xuất hiện lại**, và finding **mới** có mức ưu tiên từ `min_priority` trở lên. Payload
  có `text` cho Slack và cả danh sách có cấu trúc (`items`) cho hệ thống khác. Không gửi được thì
  chỉ ghi cảnh báo vào log — lần quét vẫn được lưu.
- Lỗi cấu hình (khoá lạ, thiếu file scope, `every` quá ngắn, lưu token thay vì mã băm…) làm
  dịch vụ **không khởi động**, thay vì chạy sai. Redis không kết nối được thì báo một dòng (mật
  khẩu trong `redis_url` được che `***`), không in traceback.

## Web API & dashboard

```bash
reconkit web --config service.toml              # http://127.0.0.1:8000 — chỉ máy này
reconkit web --config service.toml --host 0.0.0.0 --port 8000   # sau reverse proxy có TLS
```

Mở trình duyệt, dán token (`reconkit token`) vào ô đăng nhập. Dashboard (JavaScript thuần,
không thư viện ngoài, không bước build) có:

- **Overview**: số finding đang mở theo P1–P4, số *fix giả* / *xuất hiện lại*; các target trong
  `service.toml` với nút **Scan now** (chỉ vai trò `operator`); hàng đợi quét tự làm mới.
- **Runs**: mỗi run mở **bản đồ bề mặt tấn công** của M1 nguyên vẹn (cùng trang với
  `reconkit report --html`, giữ CSP riêng của nó), tải JSON hoặc SARIF.
- **Findings**: theo mức ưu tiên, lọc theo trạng thái; trang chi tiết có lịch sử vòng đời và
  form quyết định (báo đã sửa / chấp nhận rủi ro có lý do + ngày xem lại / mở lại) — ghi vào
  audit trail dưới tên của token.
- **Audit**: kiểm chuỗi băm của audit trail và các sự kiện mới nhất.

API dùng được bằng script (`Authorization: Bearer <token>`):

```bash
curl -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8000/api/v1/findings
curl -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
     -d '{"target": "office-lan"}' http://127.0.0.1:8000/api/v1/scans       # operator
curl -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8000/api/v1/runs/3/sarif -o run3.sarif
```

| Endpoint | Vai trò | |
|---|---|---|
| `GET /api/v1/me`, `targets`, `jobs`, `jobs/{id}`, `runs`, `runs/{id}`, `findings`, `findings/{id}`, `hosts`, `audit` | viewer | đọc |
| `GET /api/v1/runs/{id}/report.html`, `/sarif` | viewer | báo cáo HTML (bản đồ) / SARIF 2.1.0 |
| `POST /api/v1/scans` `{"target": "<tên>"}` | operator | xếp hàng quét một target **đã khai** |
| `POST /api/v1/findings/{id}/decision` `{"action": "claim_fixed" \| "accept" \| "reopen", "note", "until"}` | operator | quyết định |
| `POST` / `DELETE /api/v1/session` | — | đăng nhập / đăng xuất của trình duyệt |
| `GET /healthz` | — | kiểm tra sống (config, DB, Redis) cho Docker |

Bảo mật:

- Token chỉ lưu dạng SHA-256 trong `service.toml`, so sánh thời gian hằng. Sửa file là có hiệu
  lực ở request kế tiếp (gỡ token = thu hồi ngay); file sửa hỏng thì API **từ chối mọi request**
  cho tới khi sửa xong, không chạy tiếp bằng cấu hình cũ.
- Trình duyệt giữ token trong cookie **HttpOnly** (script trong trang không đọc được),
  **SameSite=Strict**, `Secure` khi chạy HTTPS. Mọi request thay đổi dữ liệu đi bằng cookie còn
  phải có header `X-ReconKit: 1` — trang web khác không gửi được header này (chống CSRF).
- Yêu cầu quét chỉ mang **tên** target; thêm bất kỳ trường nào khác (địa chỉ, scope…) là bị từ
  chối (422).
- Dữ liệu quét được coi là không tin cậy: dashboard chỉ đưa dữ liệu vào trang dưới dạng chữ
  (`textContent`), CSP chỉ cho chạy `app.js` của chính server và chỉ gọi về chính server; mọi
  response có `nosniff`, `X-Frame-Options: DENY`, `no-referrer`, `no-store`.
- Không có `/docs` (Swagger UI tải script từ CDN); schema ở `/api/v1/openapi.json`.

## Docker

Cả dịch vụ (Redis, web, worker, scheduler) chạy bằng Docker Compose:

```bash
cp deploy/service.example.toml deploy/service.toml       # sửa targets, scope (deploy/ được mount vào /config)
docker compose up -d --build
docker compose run --rm --no-deps web token --name alice --role operator   # dán khối [[tokens]] vào deploy/service.toml
# mở http://127.0.0.1:8000 — sửa service.toml có hiệu lực ngay, không cần khởi động lại
docker compose up -d --scale worker=3                    # thêm worker
docker compose logs -f worker
```

Image và compose được làm cứng theo cách làm thật:

- **Chuỗi cung ứng**: image gốc ghim theo digest; mọi gói Python ghim **phiên bản và mã băm**
  (`docker/requirements.lock`, `docker/build.lock`, sinh lại bằng `sh docker/lock.sh` ngay
  trong image gốc); nmap lấy từ kho Debian có ký. Không tải gì từ nơi khác.
- **Không chạy root**: user `reconkit` (uid 10001). nmap được `setcap cap_net_raw` — đúng một
  quyền để mở raw socket (SYN scan, traceroute) mà không cần root.
- **Ít quyền nhất**: mọi container ReconKit có root filesystem **chỉ đọc**, `cap_drop: ALL`,
  `no-new-privileges`. Chỉ **worker** được trả lại `NET_RAW` (và phải tắt `no-new-privileges`,
  vì đó là cách duy nhất để tiến trình không phải root nhận capability của file nmap). Container
  web / scheduler **không chạy được nmap** dù có bị chiếm quyền.
- Web chỉ publish ra `127.0.0.1:8000`; Redis không publish cổng nào. Muốn phục vụ máy khác:
  đặt reverse proxy có TLS phía trước (xem "Web API & dashboard").
- Healthcheck: Redis (`PING`), web (`/healthz` — cấu hình, database, hàng đợi). Log xoay vòng
  10 MB × 5.

Mạng quét: worker nằm trong mạng bridge của compose (quét ra ngoài qua NAT; traceroute thấy
gateway của Docker là hop đầu). Để quét LAN của máy chủ không qua NAT (Linux):
`network_mode: host` cho worker. Lab có lỗ hổng chạy chung mạng với worker: xem "Lab".

Dữ liệu CVE thật trong Docker:

```bash
docker compose run --rm -e NVD_API_KEY worker cve sync --cache /data/reconkit-cve.db
# rồi bật cve_cache = "/data/reconkit-cve.db" trong deploy/service.toml
```

### Sao lưu & khôi phục

```bash
reconkit backup --db reconkit.db --out-dir backups --keep 14     # ngoài Docker
docker compose exec worker reconkit backup --db /data/reconkit.db --out-dir /data/backups --keep 14
docker compose cp worker:/data/backups ./backups                 # đưa ra ngoài volume!
reconkit backup --verify backups/reconkit-20261123T042247Z.db
```

`backup` dùng API backup trực tuyến của SQLite nên **an toàn khi worker đang ghi** (chép file
DB thẳng thì có thể ra bản hỏng), mở DB nguồn ở chế độ chỉ đọc, rồi kiểm bản sao: `PRAGMA
integrity_check`, chuỗi băm của audit trail, và ghi SHA-256 vào `<file>.sha256` (đọc được bằng
`sha256sum -c`). Nó in **mã băm đầu chuỗi audit** — cất mã này ở nơi khác (ticket, email cho
khách hàng) để sau này chứng minh lịch sử không bị viết lại. `--keep N` chỉ xoá các bản
`reconkit-<thời gian>.db` cũ do chính nó tạo.

Khôi phục: `docker compose stop web worker scheduler` → `reconkit backup --verify <file>` →
chép file vào volume làm `/data/reconkit.db` → `docker compose start`. Bản sao lưu nằm cùng
volume với DB thì không chống được hỏng đĩa: luôn `docker compose cp` ra nơi khác.

Image **chưa có nuclei và subfinder** (target bật `nuclei` / `discover` sẽ báo bỏ qua scanner
không có) — xem G20.
