# Lộ trình công việc — ZuesScan

Mục tiêu: một **sản phẩm chạy được thật**, đủ chuẩn để đưa vào portfolio xin việc. Không
dùng lý do "chỉ là lab" để bỏ qua điểm yếu: chỗ nào đã nhìn ra thì sửa; đường tắt nào cố ý
giữ tạm phải ghi vào [`docs/KNOWN-GAPS.md`](docs/KNOWN-GAPS.md) (mã `G1`…`G26`).

Quy trình: mỗi task = 1 nhánh (`feat/` · `fix/` · `refactor/` · `chore/` · `docs/`), chạy đủ
pytest + ruff + mypy trước khi commit, rồi `git merge --no-ff` vào `main` và push (từ
2026-11-07 merge ở local thay cho PR; `--no-ff` giữ nhánh hiện rõ trong lịch sử). Lộ trình học
song song: [`docs/LO-TRINH-HOC.md`](docs/LO-TRINH-HOC.md). Tầm nhìn & các quyết định thiết kế
đã chốt (D1–D8): [`docs/THIET-KE.md`](docs/THIET-KE.md).

Cập nhật lần cuối: 2026-11-24.

## Giai đoạn 1 — Lát cắt dọc (CLI) ✅

- [x] `chore/scaffold` — layout package, pyproject, pytest, lint. (PR #1)
- [x] `feat/schema` — `Asset` / `Service` / `Finding` + fingerprint. (PR #2)
- [x] `feat/scope` — allowlist/denylist. (PR #3)
- [x] `feat/plugin-nmap` — interface plugin + adapter nmap. (PR #4)
- [x] `feat/integration` — SQLite + orchestrator + CLI end-to-end. (PR #5)
- [x] `feat/cve` — bước CVE offline, nguồn CVE cắm được. (PR #6)
- [x] `docs/known-gaps` — rà soát điểm yếu + lộ trình này. (PR #8)

## Giai đoạn 1.5 — Sửa nền móng ✅

Sửa **trước khi** thêm tính năng mới, vì những thứ này càng để lâu càng khó sửa: hợp đồng
plugin (mọi plugin sau này phải theo), schema DB và fingerprint (dữ liệu tích lũy theo
format cũ), và lớp an toàn scope.

| # | Nhánh | Sửa | Vì sao ở vị trí này |
|---|---|---|---|
| F1 ✅ | `chore/ci` | G17 — GitHub Actions chạy pytest + ruff + mypy | Có trước để mọi PR sửa lỗi sau đều được kiểm tự động |
| F2 ✅ | `fix/scope-deny-overlap` | G4 (phần denylist: dải IP chồng lấn deny; chú thích cuối dòng; entry không hợp lệ → lỗi) | Lỗi an toàn nghiêm trọng nhất, sửa nhỏ, độc lập |
| F3 ✅ | `fix/scan-errors` | G3 — bọc lỗi subprocess thành `ScanError`, CLI báo lỗi rõ | Độc lập; cần có trước F4 để plugin mới dùng luôn |
| F4 ✅ | `fix/no-plugin-available` | G2 — không plugin nào chạy được → lỗi, không lưu run "sạch" | Nhỏ; sửa cả câu sai trong README |
| F5 ✅ | `refactor/per-host-assets` | G1 + G16 — plugin trả kết quả theo từng host, điền `Asset.ip` | Đổi hợp đồng plugin: phải xong trước khi thêm subfinder/nuclei |
| F6 ✅ | `fix/scope-resolve` | G4 (phần DNS) — phân giải 1 lần, kiểm mọi IP, quét bằng IP, `--exclude`, kiểm lại sau quét | Cần F2 + F5 (có danh sách host để kiểm lại) |
| F7 ✅ | `refactor/storage-schema` | G5 + G14 + G15 — `finding.service_id`, `scan_run.status/error`, phiên bản tool theo từng scanner, index FK, cascade, `schema_version` + migration; lần quét thất bại được lưu thành run `failed` | Đổi schema DB trước khi có dữ liệu thật tích lũy |
| F8 ✅ | `fix/fingerprint-identity` | G12 — fingerprint theo IP + port + protocol + CVE/rule id, có số công thức (`v2:`); orchestrator là nơi duy nhất đặt fingerprint | Phải ổn định trước `feat/diff` |
| F9 ✅ | `feat/evidence` | G13 — plugin trả `ScanResult` kèm output gốc; lưu nén + SHA-256 theo run; `zues raw`; điền `evidence` | Cần F7 (schema) |

## Cột mốc M1 — Báo cáo HTML có bản đồ ✅

Mục tiêu: **nhìn thấy** bề mặt tấn công sớm, trước khi xây web server. Chỉ làm được sau F5
(dữ liệu theo từng host) và F7 (finding gắn với service).

- [x] `feat/nmap-traceroute` — plugin nmap thêm `--traceroute` (cờ `scan --traceroute`; profile
      `full` sẽ bật sẵn), lưu các hop của từng host (bảng `route_hop`, schema DB v5) → vẽ đường
      đi máy quét → router → dải mạng. Hop chỉ được *nhìn thấy*, không bị quét: probe luôn gửi
      tới host trong scope. Đã kiểm với nmap thật trên 127.0.0.1 (không có route, CLI giải
      thích); ✅ hop thật đã kiểm trên lab Docker có router (`feat/lab`: 10.66.1.254).
- [x] `feat/report-html` — `zues report [--run <id>] --html <file>`: một file HTML duy nhất,
      nhúng sẵn dữ liệu (JSON) + Cytoscape.js 3.34.4 (vendored, ghim SHA-256), mở offline. Bản
      đồ đọc từ trái sang phải: máy quét → router → dải mạng ⊃ host ⊃ service → finding; bấm
      vào node / dòng bảng để xem chi tiết. Dữ liệu quét coi là không tin cậy: JSON được escape,
      trang chỉ ghi text, CSP chỉ cho chạy code có hash và cấm mọi kết nối mạng. Kèm
      `zues runs` (danh sách run). Phần Python chỉ dùng thư viện chuẩn. (G18 — phần HTML)

## Giai đoạn 2 — Mở rộng theo chuẩn thực tế

- [x] `feat/cve-matching` — khớp CVE theo CPE + dải phiên bản (định dạng `cpeMatch` của NVD),
      chuẩn hoá version (`7.4p1 Debian 10+deb9u7` → 7.4 + p1 + gói distro), alias vendor
      nmap ↔ NVD, `Finding.confidence` (`tentative` khi là gói của distro vì có backport).
      (G8, G10)
- [x] `feat/nvd-source` — `zues cve sync` tải NVD API 2.0 về cache SQLite (phân trang,
      tôn trọng rate limit, retry, lần sau chỉ tải phần thay đổi), `scan --cve-cache`. (G9)
- [x] `feat/cve-priority` — CVSS score/vector, CWE, CISA KEV, FIRST EPSS trên mỗi finding (schema
      DB v8); xếp ưu tiên P1 (đang bị khai thác) → P4; bản đồ chỉ vẽ 5 lỗi gấp nhất mỗi cổng.
      (G11)
- [x] `feat/scan-profiles` — profile `quick` / `standard` / `full` / `gentle`, file cấu hình TOML
      (`--config`), cờ ghi đè (`--ports`, `--timing`, `--max-rate`, `--timeout`…), lệnh
      `zues profiles`; mỗi run lưu profile + thông số (schema DB v6). (G6, G7)
- [x] `feat/ipv6` — phân giải cả AAAA, mọi địa chỉ phải trong scope, nmap `-6` chạy riêng cho
      nhóm IPv6, `--ipv4-only`, chặn quét dải IPv6 lớn hơn /112. (G22)
- [x] `feat/audit-trail` — mỗi run lưu người chạy, engagement, file scope (đường dẫn + SHA-256
      + nội dung), kế hoạch quét đã duyệt; nhật ký audit dạng chuỗi băm (quét / từ chối / xóa),
      `zues audit --verify`; scope có `@engagement`, `@expires`, `@window`. (G21)
- [x] `feat/diff` — kho tài sản (`inv_host` / `inv_service` / `inv_finding`: lần thấy đầu /
      cuối, trạng thái) + lịch sử (`finding_event`), schema DB v11; vòng đời lỗi: mới → mở →
      báo sửa → **đã xác minh vá** / **fix giả** ⚠, biến mất, tái xuất hiện ⚠, chấp nhận rủi ro
      (lý do + hạn xem lại); chỉ kết luận "đã hết" khi run thực sự nhìn vào. `zues
      inventory`, `findings`, `finding`, `diff`. (D1)
- [x] `feat/report-json-sarif` — `zues report --json` / `--sarif` (SARIF 2.1.0). (G18)
- [x] `feat/logging` — logger theo module, `-v` / `-vv`, `--log-file`, `--log-format json`. (G19)
- [x] `feat/plugin-subfinder` — `scan --discover`: subfinder tìm subdomain (thụ động), scope có
      wildcard `*.example.com`; mỗi tên vẫn phải phân giải ra địa chỉ trong scope mới được quét.
- [x] `feat/plugin-nuclei` — `scan --nuclei`: nuclei chạy trên dịch vụ web nmap tìm được, URL
      theo địa chỉ đã duyệt, vhost qua Host/SNI, mặc định an toàn (không interactsh, không
      template dos/fuzz/intrusive, giới hạn tốc độ); lỗi CVE quan sát được là `confirmed`.
- [x] `feat/authenticated-scan` — `scan --credentials`: đăng nhập SSH bằng key, đọc gói đã cài,
      đối chiếu Debian Security Tracker; rút lại các finding đoán theo banner khi gói đã có bản vá
      (backport). Ubuntu chưa hỗ trợ.

## Giai đoạn 3 — Dịch vụ chạy nền

- [x] `feat/worker-queue` — `service.toml` (chỉ target đã khai mới quét được), hàng đợi
      Redis + RQ, `zues worker` (fork trên Linux, chạy tại chỗ trên Windows), `zues
      scheduler` (`every = "24h"`, khoá mỗi vòng), `zues enqueue`, `zues token`, cảnh
      báo webhook: fix giả / xuất hiện lại / finding mới ≥ `min_priority`. Còn lại: G23.
- [x] `feat/web` — `zues web`: API JSON `/api/v1` (FastAPI) + dashboard JavaScript thuần
      (D5): target & hàng đợi (nút "Scan now"), danh sách run mở bản đồ M1 nguyên vẹn, finding
      theo mức ưu tiên với form quyết định, audit trail có kiểm chuỗi băm. Token Bearer cho
      script; trình duyệt dùng cookie HttpOnly + SameSite=Strict + header chống CSRF; vai trò
      viewer / operator; `service.toml` đổi là có hiệu lực ngay (thu hồi token), hỏng thì từ chối
      mọi request. Còn lại: G23.
- [x] `chore/docker` — `Dockerfile` (không root, nmap chỉ `cap_net_raw`, phụ thuộc ghim theo mã
      băm), `compose.yaml` (Redis + web + worker + scheduler, FS chỉ đọc, `cap_drop: ALL`),
      `zues backup` (sao lưu trực tuyến có kiểm tra, `--verify`, `--keep`); CI build và
      quét thử trong container. ✅ ảnh demo (`feat/lab`), nuclei/subfinder (`chore/docker-tools`).
- [x] `feat/lab` — `lab/`: Apache 2.4.49, OpenSSH 7.5 (DMZ) và nginx 1.20.0 sau một router NAT
      (mạng internal), hai mạng cách ly (không Internet, không chạm host); `up.sh` / `demo.sh` /
      `down.sh`; kịch bản vòng đời cho ra "fixed" và "fake fix" thật. Ảnh demo trong README (G20).

## Giai đoạn 4 — Công cụ ngoài chạy thật (nuclei, subfinder)

Hai plugin đã có từ giai đoạn 2 nhưng mới được test bằng output mẫu. Giai đoạn này chạy chúng
thật (nuclei 3.11.1, templates 10.5.2, subfinder 2.17.0), sửa những gì chạy thật làm lộ ra, và
đưa chúng vào image Docker và lab. Ghi chép: G24, Bài 8.

- [x] `feat/tool-runtime` — nuclei: templates ghim chạy offline với cấu hình riêng, `-dut`, bỏ
      `info`, dịch vụ không phải web qua `ip:port` + template mạng, chung một giới hạn thời gian,
      hết giờ / lỗi không làm mất kết quả nmap (run `partial`), gộp finding trùng giữ dữ liệu
      KEV/CVSS. subfinder: provider config (`--subfinder-config`), home tạm; discovery:
      `--discover-limit`, phân giải song song, lọc wildcard DNS, ghi chú gộp.
- [x] `chore/docker-tools` — nuclei, subfinder, templates trong image: ghim phiên bản + SHA-256
      từ file checksums chính thức (nay: `zues_scan/data/tools.lock`), cập nhật một lệnh, chỉ lấy
      đúng binary, giải nén an toàn; CI kiểm phiên bản trong image khớp lock. Image 182 → 401 MB.
- [x] `feat/lab-nuclei` — Apache trong lab cấu hình khai thác được (như vulhub) để nuclei xác
      nhận CVE-2021-41773; target lab bật nuclei với profile `lab`; profile có `check_rate` riêng
      (request/giây của nuclei) tách khỏi `max_rate` (gói/giây của nmap); `zues finding`
      hiện độ tin cậy; CI kiểm `confirmed`, Terrapin và phiên bản templates trong run.

## Giai đoạn 5 — Dễ cài, dễ mở rộng, cho AI dùng

Mục tiêu: mang ZuesScan sang máy khác mà cài nhanh, thêm / bớt công cụ không phải sửa code, và
để một AI (qua MCP) dùng được ZuesScan một cách an toàn.

- [x] `feat/doctor` — `zues doctor [--config] [--json]`: công cụ, phiên bản, quyền raw socket
      của nmap, templates, key của subfinder, dữ liệu CVE, gói dịch vụ, Redis; lệnh cài đúng cho
      từng hệ điều hành; không tự cài gói hệ thống. Tìm ra và sửa: image thiếu SSH client,
      `subfinder -version` ghi cấu hình vào `/data`.
- [x] `feat/plugin-registry` — registry + entry points `zues_scan.plugins`; `--scanner/--check/
      --discoverer` và `scanners/checks/discoverers` trong `service.toml`; mỗi plugin khai
      `activity`, scope đặt trần `@activity` (mặc định `scan` → nuclei cần `@activity active`);
      `zues plugins`; `zues_scan.plugins.contract`; gói mẫu `examples/zues-exposed-git`;
      `docs/PLUGINS.md`; doctor kiểm cả plugin ngoài. Còn lại: G25.
- [x] `feat/tools-install` — `zues tools list|install|verify|path`: nuclei, subfinder,
      nuclei-templates ghim phiên bản + SHA-256 cho Linux / macOS (amd64, arm64) và Windows
      amd64, cài vào thư mục của người dùng, không cần admin; ghi hash của thứ đã cài để `verify`.
      `zues_scan/tools.py` + `zues_scan/data/tools.lock` thay `docker/tools.*` (image dựng bằng
      chính chúng). Plugin tìm công cụ: bản ZuesScan cài → PATH → chỗ bộ cài nmap của Windows.
      Đã thử thật trên Windows (cài, verify, doctor dùng được) và Linux (image).
- [x] `chore/release` — `__version__` là nguồn duy nhất (0.2.0), `zues --version`,
      `CHANGELOG.md`; workflow Release theo tag: kiểm tag/version/changelog, wheel + sdist (cài thử),
      image amd64 + arm64 có SBOM + provenance, ký cosign keyless, quét Trivy, GitHub Release; chạy
      tay = chạy thử không phát hành; action ghim SHA; `ZUES_IMAGE` cho compose. Chưa đẩy tag
      đầu tiên (việc phát hành do người duy trì quyết); PyPI chờ chọn tên.
- [x] `feat/mcp` — `zues mcp` (SDK MCP 2.3, stdio, `zues-scan[mcp]`): 12 tool qua web API;
      `request_scan` / `claim_fixed` / `reopen_finding` cần người dùng xác nhận (elicitation qua
      `Resolve`, không phải tham số); không có tool chấp nhận rủi ro; chỉ target đã khai báo; dữ
      liệu quét làm sạch + đánh dấu không tin cậy. Thử thật qua stdio trên lab. Còn lại: G26.
- [x] `chore/rename-zuesscan` — ReconKit → **ZuesScan** (gói `zues-scan`, import `zues_scan`, lệnh
      `zues`, biến `ZUES_*`); dữ liệu cũ vẫn đọc được (cột `reconkit_version`, định dạng
      `reconkit-cve`, `.reconkit-version`, bản sao lưu `reconkit-*.db`).
- [x] `feat/dnsx` — plugin discovery dnsx: dò `<từ>.<tên miền>` bằng wordlist riêng (~370 tên)
      hoặc `--dns-wordlist`, mức `scan`, tốc độ theo `check_rate`, lọc wildcard DNS, resolver của
      hệ thống; ghim trong tools.lock, có trong image, doctor kiểm. Sửa `zues plugins` không
      thấy công cụ do `zues tools install` cài. Thử thật với CoreDNS. Còn lại: G27.
- [x] `feat/naabu` — scanner naabu: nmap `-sn` dò host sống → naabu connect scan (không cần
      root) → nmap `-sV` chỉ trên cổng mở; ghim trong tools.lock, có trong image, doctor kiểm;
      scanner báo `incomplete` giờ làm run `partial`. Đo thật trên lab: cùng kết quả, chậm hơn nmap
      trên LAN (quick 13 s / 8 s; toàn cổng 40 s / 13 s) — ghi rõ trong README. Còn lại: G28.
- [x] `feat/httpx` — check httpx: lớp web của mỗi dịch vụ (URL, trạng thái, tiêu đề, server, công
      nghệ) lưu vào `Service.web` (schema 13), hiện ở CLI / bản đồ / API / MCP; công nghệ có phiên
      bản → bước CVE, cùng CVE với nmap thành một finding. Lab chạy httpx + nuclei; CI kiểm.
      Thử thật trên lab (Apache 2.4.49, nginx 1.20.0 "Welcome to nginx!"). Còn lại: G29.
- [x] `feat/managed-config` — vai trò `admin`; scope / target / token lưu trong database (schema 14)
      cạnh `service.toml` (chỉ đọc, thắng khi trùng tên); API `/api/v1/admin/*`; kiểm như lúc quét
      trước khi lưu; audit `config`; có hiệu lực ngay (cả từ tiến trình khác); `zues user add`.
      Còn lại: G30.
- [x] `feat/settings-ui` — trang Settings của dashboard (admin): bảng target / scope / token, form
      scope có mẫu, form target chọn tool theo loại (mức chủ động, đã cài chưa), token hiện một lần.
      Thử thật bằng Chrome headless: thêm scope, target, target ngoài scope bị từ chối kèm lý do,
      tạo token, trang Edit điền sẵn. Sửa: trang cũ trả lời muộn vẽ đè trang mới; `pattern` không
      hợp lệ ở chế độ regex `v` của trình duyệt.
- [x] `feat/easy-install` — không bắt buộc `service.toml`: cài đặt từ biến môi trường `ZUES_*`,
      target / scope / token từ dashboard; compose chạy ngay (`up -d` → `zues user add` →
      Settings); lab giữ file qua `ZUES_CONFIG`. Thử thật trên volume trống: admin → scope →
      target → Scan now → run được lưu.
- [x] `chore/release-0.2.0` — phát hành v0.2.0 (chủ dự án đồng ý 2026-11-24): CHANGELOG gộp phần
      Unreleased vào 0.2.0; tag `v0.2.0` chạy workflow Release. Lần chạy đầu hỏng ở bước ký cosign
      (tên owner viết hoa; `fix/release-lowercase-image`); chủ dự án chọn dời tag sang bản sửa thay
      vì ra 0.2.1 — lần chạy lại xanh hết: GitHub Release, wheel + sdist, image amd64 + arm64 đã ký.

## Giai đoạn 6 — Đóng các giới hạn còn lại (G23–G30)

Những gì `KNOWN-GAPS.md` còn ghi "Còn lại", làm theo thứ tự rủi ro: an toàn của dịch vụ trước,
rồi độ tin cậy, rồi tiện dụng.

- [x] `feat/web-sessions` (G23) — phiên do server giữ (schema 15): cookie chỉ là khoá ngẫu nhiên
      của phiên; hết khi đăng xuất, 30 phút không dùng, 8 giờ, token bị thu hồi / cấp lại, admin
      kết thúc (Settings → Sessions); 10 token sai / 15 phút → khoá địa chỉ 15 phút (Redis, dự
      phòng trong tiến trình); audit `auth`. Thử bằng Chrome headless trên dịch vụ thật.
- [x] `fix/scheduler-reload` (G30) — scheduler đọc lại cấu hình mỗi vòng: target thêm trên
      dashboard trước đây không bao giờ được quét định kỳ nếu không khởi động lại scheduler.
- [x] `feat/alert-outbox` (G23) — cảnh báo chờ trong database (schema 16) tới khi gửi được: ghi
      cùng transaction với run, worker gửi ngay, scheduler gửi lại (backoff, `Retry-After`, bỏ cuộc
      sau 24 giờ), ký HMAC có timestamp; cảnh báo mới: quét hỏng N lần liền / chạy lại, quét không
      bắt đầu được, job hỏng, bị khoá đăng nhập; Settings → Alerts; compose truyền biến cảnh báo.
      Thử thật: webhook 503 → chờ → gửi lại được, chữ ký hợp lệ; nút gửi thử trên Chrome headless.
- [x] `feat/sqlite-wal` (G23) — database ở chế độ WAL: đọc dài không chặn lưu run (test đối
      chứng), chờ ghi 15 giây; bật khi tạo / migrate DB và khi dịch vụ khởi động, không bao giờ chỉ
      vì mở DB (bản backup giữ nguyên mã băm); backup là một file; doctor báo chế độ; README khôi
      phục xoá `-wal` / `-shm` cũ.
- [x] `feat/cron-schedule` (G23) — `cron = "0 2 * * sat Asia/Ho_Chi_Minh"` (crontab 5 trường, múi
      giờ IANA / độ lệch, ≥ 5 phút) trong service.toml, API, dashboard; scheduler giữ mốc lịch nên
      `every` không còn trôi theo thời gian chờ; lỡ nhiều mốc thì bù một lần. Thử trên Chrome
      headless (lưu, từ chối `*/2`, trang Edit, Overview).
- [x] `feat/web-compare` (G23) — so sánh hai run trên web (Changes / Compare, API `/runs/{id}/diff`,
      tool MCP `compare_runs`), phân trang runs (`before`) và findings (`limit` / `offset`,
      `X-Total-Count`); `diff.previous_run` dùng chung cho CLI, web, MCP. Thử trên Chrome headless.
- [x] `feat/evidence-redaction` (G24) — request / response của nuclei được che trước khi lưu và
      băm (header đăng nhập / phiên, mẫu bí mật, thân response 2 KB); không có gì để che thì giữ
      nguyên từng byte; `zues_scan/redact.py` chỉ dùng thư viện chuẩn.
- [x] `feat/token-expiry` (G23, G30) — token có hạn dùng (schema 17, mặc định 90 ngày, `expires` trong
      service.toml), hết hạn thì từ chối rõ ràng + phiên kết thúc, cảnh báo một tuần trước hạn;
      Rotate trên Settings / `zues user rotate` / API. Thử trên Chrome headless.
- [x] `fix/core-tests-token` — test xoay vòng token import web server trong job core (không có
      FastAPI): mọi job core của 0538e6a hỏng. Bài học cũ được áp lại: chạy container sạch.
- [x] `fix/nuclei-network-timeouts` (G24) — job lab chập chờn được tìm ra nguyên nhân: template
      mạng của nuclei dùng timeout của HTTP; sshd chậm → lỡ Terrapin 4/10 lần; nay 30 s / 3 lần
      thử (5/5). CI báo kiểm tra nào hỏng + bảng finding thành annotation công khai.
- [x] `feat/config-alerts` (G30) — mọi thay đổi scope / target / token (dashboard, `zues user`) gửi
      cảnh báo `config_changed` (ai, làm gì), cùng transaction với sự kiện audit.
- [x] `feat/scope-approval` (G30, D12) — hai người cho thay đổi scope khi bật `scope_approval`:
      đề xuất (lý do) → admin khác duyệt / từ chối, người đề xuất rút; không tự duyệt, không duyệt
      bằng token người đề xuất từng thấy giá trị; đề xuất cũ không duyệt được; diff trong Settings.
      Thử trên Chrome headless (đề xuất, bị chặn trước khi Rotate, duyệt, audit).
- [x] `feat/target-permissions` (G23, D13) — token viewer / operator giới hạn vào target theo mẫu
      tên (Settings, `zues user`, service.toml, API); chỉ thấy / làm trên target đó (run, finding,
      host, job, quét, MCP), còn lại 404; audit chỉ cho token không giới hạn; run ghi
      `target_name` (schema 19), run cũ được gán khi khởi động. Thử trên Chrome headless.

