# Lộ trình công việc — ReconKit

Mục tiêu: một **sản phẩm chạy được thật**, đủ chuẩn để đưa vào portfolio xin việc. Không
dùng lý do "chỉ là lab" để bỏ qua điểm yếu: chỗ nào đã nhìn ra thì sửa; đường tắt nào cố ý
giữ tạm phải ghi vào [`docs/KNOWN-GAPS.md`](docs/KNOWN-GAPS.md) (mã `G1`…`G20`).

Quy trình: mỗi task = 1 nhánh (`feat/` · `fix/` · `refactor/` · `chore/` · `docs/`), chạy đủ
pytest + ruff + mypy trước khi commit, rồi `git merge --no-ff` vào `main` và push (từ
2026-11-07 merge ở local thay cho PR; `--no-ff` giữ nhánh hiện rõ trong lịch sử). Lộ trình học
song song: [`docs/LO-TRINH-HOC.md`](docs/LO-TRINH-HOC.md). Tầm nhìn & các quyết định thiết kế
đã chốt (D1–D8): [`docs/THIET-KE.md`](docs/THIET-KE.md).

Cập nhật lần cuối: 2026-11-22.

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
| F9 ✅ | `feat/evidence` | G13 — plugin trả `ScanResult` kèm output gốc; lưu nén + SHA-256 theo run; `reconkit raw`; điền `evidence` | Cần F7 (schema) |

## Cột mốc M1 — Báo cáo HTML có bản đồ ✅

Mục tiêu: **nhìn thấy** bề mặt tấn công sớm, trước khi xây web server. Chỉ làm được sau F5
(dữ liệu theo từng host) và F7 (finding gắn với service).

- [x] `feat/nmap-traceroute` — plugin nmap thêm `--traceroute` (cờ `scan --traceroute`; profile
      `full` sẽ bật sẵn), lưu các hop của từng host (bảng `route_hop`, schema DB v5) → vẽ đường
      đi máy quét → router → dải mạng. Hop chỉ được *nhìn thấy*, không bị quét: probe luôn gửi
      tới host trong scope. Đã kiểm với nmap thật trên 127.0.0.1 (không có route, CLI giải
      thích); hop thật sẽ được kiểm trên lab Docker có router (Giai đoạn 3).
- [x] `feat/report-html` — `reconkit report [--run <id>] --html <file>`: một file HTML duy nhất,
      nhúng sẵn dữ liệu (JSON) + Cytoscape.js 3.34.4 (vendored, ghim SHA-256), mở offline. Bản
      đồ đọc từ trái sang phải: máy quét → router → dải mạng ⊃ host ⊃ service → finding; bấm
      vào node / dòng bảng để xem chi tiết. Dữ liệu quét coi là không tin cậy: JSON được escape,
      trang chỉ ghi text, CSP chỉ cho chạy code có hash và cấm mọi kết nối mạng. Kèm
      `reconkit runs` (danh sách run). Phần Python chỉ dùng thư viện chuẩn. (G18 — phần HTML)

## Giai đoạn 2 — Mở rộng theo chuẩn thực tế

- [ ] CVE thật: khớp CPE + dải phiên bản, chuẩn hóa version (G8); `NvdCveSource` đồng bộ
      NVD API 2.0 về cache local (G9); `Finding.confidence` cho vấn đề backport (G10);
      CVSS score/vector, CWE, KEV, EPSS + xếp ưu tiên (G11).
- [x] `feat/scan-profiles` — profile `quick` / `standard` / `full` / `gentle`, file cấu hình TOML
      (`--config`), cờ ghi đè (`--ports`, `--timing`, `--max-rate`, `--timeout`…), lệnh
      `reconkit profiles`; mỗi run lưu profile + thông số (schema DB v6). (G6, G7)
- [ ] IPv6: phân giải AAAA, kiểm scope, chạy nmap `-6` riêng (G22).
- [ ] Dấu vết kiểm toán: `scan_run` lưu mã băm file scope, người chạy, tham chiếu giấy phép
      (G21).
- [ ] `feat/diff` — so fingerprint giữa các lần quét: lỗi mới / đã hết / fix giả. Kèm mô hình
      dữ liệu lai: kho tài sản (`first_seen` / `last_seen`, trạng thái finding) + lịch sử
      từng run (`observation`, `finding_event`) — xem D1.
- [ ] Báo cáo JSON / SARIF (G18; HTML đã có từ M1); `logging` + `--verbose` (G19).
- [ ] Plugin `subfinder` (subdomain, cần wildcard scope), `nuclei` (template checks).
- [ ] (Nâng cao) Quét có đăng nhập — đối chiếu gói đã cài với Debian/Ubuntu security tracker.

## Giai đoạn 3 — Dịch vụ chạy nền

- [ ] Scheduler + queue (Redis + RQ) + worker.
- [ ] Web API (FastAPI) + Web UI dùng lại code vẽ bản đồ của M1 + thông báo. Thư viện web
      đặt trong gói tuỳ chọn `reconkit[server]`, lõi vẫn không phụ thuộc.
- [ ] Đóng gói Docker Compose + volume + backup DB; README có demo (G20).
- [ ] Lab mục tiêu (Metasploitable / container có lỗ hổng) trong network nội bộ.
