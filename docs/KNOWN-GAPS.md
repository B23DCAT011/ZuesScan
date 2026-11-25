# Điểm yếu đã biết & kế hoạch nâng cấp — ZuesScan

Danh sách các chỗ ZuesScan **chưa đạt chuẩn sản phẩm thật**, kèm dẫn chứng trong code và
hướng sửa theo cách làm ngoài thực tế. Nguyên tắc: điểm yếu nào đã nhìn ra thì phải sửa,
không dùng lý do "chỉ là lab". Đường tắt nào cố ý giữ tạm thời cũng phải ghi vào đây.

Mỗi mục sửa xong = 1 nhánh = 1 PR; đánh dấu `[x]` và ghi số PR khi merge.

Rà soát lần đầu: 2026-10-28 (trên `main` sau PR #6).

---

## Mức 1 — Chạy sai / hỏng (ưu tiên sửa ngay)

- [x] **G1. Quét dải CIDR gộp mọi máy thành một Asset.**
  - ✅ **Đã sửa (F5)**: hợp đồng plugin đổi thành `scan(target) -> list[Asset]`, mỗi host
    một `Asset`. Plugin nmap đọc `<status>`, `<address>`, `<hostnames>`: `Asset.ip` là địa
    chỉ IPv4/IPv6 (bỏ qua MAC), `Asset.host` là tên người dùng gõ (`type="user"`) nếu có,
    không thì là IP; host up mà không có cổng mở vẫn là một asset. Orchestrator gộp báo cáo
    của nhiều plugin về cùng một máy (so IP; thiếu IP thì so tên). CLI in theo từng host.
    Đã kiểm với nmap thật: `127.0.0.0/30` → 4 asset riêng.
  - Còn lại: tên PTR và trường hợp một máy nhiều hostname chưa được lưu (→ D1, làm cùng
    kho tài sản). Host được trả về chưa được kiểm lại với scope (→ F6).
  - Dẫn chứng: `orchestrator.py` tạo một `Asset(host=target)` duy nhất; `NmapPlugin.parse_xml()`
    duyệt mọi `<host>` nhưng bỏ địa chỉ, trả về một danh sách `Service` phẳng.
  - Hậu quả: quét `10.0.0.0/24` ra một "máy" tên `10.0.0.0/24`; không biết cổng nào của máy
    nào; hai máy cùng lỗi sinh ra hai finding trùng fingerprint (mất một lỗi thật khi diff).
  - Sửa: plugin trả kết quả **theo từng host** (đọc `<address>`, `<hostnames>`); orchestrator
    gộp theo IP; điền `Asset.ip`.

- [x] **G2. Không có nmap vẫn báo quét thành công.**
  - Dẫn chứng: `orchestrator.py` — `if not plugin.is_available(): continue`.
  - Hậu quả: lưu một lần quét 0 service, người dùng tưởng máy sạch.
  - Sửa: không plugin nào chạy được → báo lỗi rõ ràng, không lưu run "thành công".
  - **Lỗi đi kèm (đã xác nhận với nmap 7.92): nmap thoát code 0 dù không quét được gì.**
    Tên không phân giải được → `<hosts up="0" down="0" total="0"/>`, lý do chỉ nằm ở stderr.
    Host không trả lời → `<hosts up="0" down="1" total="1"/>`, không có thẻ `<host>` nào.
    Cả hai trước đây đều được lưu thành run 0 service.
  - ✅ **Đã sửa (F4)**: orchestrator ném `NoPluginAvailableError` khi không plugin nào chạy
    được (kiểm tra *sau* scope); plugin bị bỏ qua trong khi plugin khác vẫn chạy được ghi
    vào `ScanRun.skipped_plugins` và CLI in cảnh báo. Plugin nmap đọc `runstats/hosts`:
    `total = 0` hoặc `up = 0` → `ScanError`. CLI trả exit code 4, không lưu run.
  - Còn lại: ~~`skipped_plugins` chưa lưu vào DB~~ (✅ F7: bảng `scan_run_plugin`, run
    thiếu scanner có `status = partial`). "Host không trả lời" hiện là *lỗi* (từ F7 được lưu
    thành run `failed`) vì chưa có chỗ ghi trạng thái từng host; khi có (D1) nó sẽ thành
    một quan sát được lưu lại. Quét dải mà chỉ một phần host trả lời: từ F5 CLI in
    "N responded of M addresses", nhưng chưa liệt kê địa chỉ nào im lặng (→ D1).

- [x] **G3. nmap lỗi / quá thời gian làm chương trình crash.**
  - Dẫn chứng: `cli.py` chỉ bắt `RuntimeError`; `subprocess.CalledProcessError` và
    `subprocess.TimeoutExpired` không phải `RuntimeError`.
  - Hậu quả: in traceback Python thay vì thông báo lỗi.
  - Sửa: plugin bọc lỗi subprocess thành một exception riêng (vd `ScanError`) kèm stderr;
    CLI bắt và trả exit code rõ ràng.
  - ✅ **Đã sửa (F3)**: `ScanError` nằm trong `plugins/base.py` (thuộc hợp đồng plugin).
    Plugin nmap bọc 5 trường hợp: thiếu binary, không khởi chạy được (`OSError`), exit code
    khác 0 (kèm stderr của nmap), quá thời gian, XML hỏng / bị cắt. CLI in
    `scan failed [nmap]: …`, trả exit code 4 và **không lưu run** vào DB. Output của nmap
    được đọc theo UTF-8 thay vì codepage của Windows.

- [x] **G4. Scope chỉ kiểm tra chuỗi nhập vào, không kiểm tra IP thật.**
  - ✅ **Đã sửa phần DNS (F6)**: `Scope.plan()` là cổng duy nhất trước khi quét. Tên miền
    được phân giải **một lần** (IPv4), **mọi** IP phải nằm trong allowlist và không dính
    deny, nếu không → `ScopeError` nêu rõ IP. Plugin nhận `ScanTarget` (danh sách IP đã
    duyệt + danh sách loại trừ) nên nmap không bao giờ tự phân giải tên → hết TOCTOU, và
    quét đủ mọi IP của tên. Dải chồng lấn deny được quét với `--exclude`; target bị deny
    phủ kín (kể cả phủ từng mảnh) thì từ chối. Orchestrator kiểm lại từng host trong kết
    quả: host ngoài scope bị loại, ghi vào `ScanRun.out_of_scope`, CLI cảnh báo. Tên không
    phân giải được → `ResolutionError`, exit 4. Đã kiểm với nmap + DNS thật.
  - Hệ quả cho người dùng: file scope chỉ có tên miền là **không đủ**, phải khai cả IP/dải.
  - Còn lại: ~~wildcard `*.example.com`~~ (✅ `feat/plugin-subfinder`: `*.example.com` cho phép
    *tên* dưới example.com; mỗi tên vẫn phải có mọi địa chỉ trong allowlist); ~~IPv6~~ (✅ G22); ~~quét bằng IP làm
    mất tên miền ở tầng HTTP (virtual host / SNI)~~ ✅ nuclei gửi tên qua Host header + SNI
    trong khi vẫn kết nối tới địa chỉ đã duyệt. ~~`out_of_scope` chưa lưu vào DB~~ (✅ F7).
  - Dẫn chứng: `scope.py` so khớp hostname, không phân giải DNS.
  - Hậu quả: domain trong allowlist nhưng trỏ tới IP ngoài phạm vi vẫn bị quét — lỗ hổng ở
    chính lớp an toàn.
  - **Lỗi đi kèm (đã xác nhận): denylist bị vượt qua bằng dải IP.** Scope
    `10.0.0.0/24` + `!10.0.0.1` → `is_allowed("10.0.0.1")` = False nhưng
    `is_allowed("10.0.0.0/24")` = True, nên nmap vẫn quét 10.0.0.1. Nguyên nhân: deny chỉ
    kiểm tra "target nằm *trong* deny" (`subnet_of`) thay vì "target *chồng lấn* deny"
    (`overlaps`). ✅ **Đã sửa (F2)**: dải chồng lấn deny bị từ chối cả dải (fail closed).
  - **Lỗi đi kèm thứ hai (đã xác nhận): chú thích cuối dòng vô hiệu hóa dòng deny.**
    `!10.0.0.1   # router` không parse được thành IP nên bị lưu thành *hostname* rác, IP
    vẫn quét được. Gốc rễ: chuỗi nào không phải IP thì bị *đoán* là hostname. ✅ **Đã sửa
    (F2)**: `#` là chú thích ở mọi vị trí; entry không hợp lệ → `ScopeError` kèm số dòng,
    CLI exit 2.
  - Khác: nmap mặc định chỉ quét IP đầu tiên của hostname; DNS có thể đổi giữa lúc kiểm tra
    và lúc quét (TOCTOU); chưa hỗ trợ wildcard `*.example.com`.
  - Sửa: phân giải hostname **một lần**, **mọi IP** phải nằm trong scope, rồi đưa **IP**
    (không phải hostname) cho nmap; dải chồng lấn deny → truyền `--exclude` cho nmap;
    kiểm tra lại scope cho từng host trong kết quả (liên quan G1, subfinder sau này).

- [x] **G5. Đọc finding từ DB mất thông tin service.**
  - ✅ **Đã sửa (F7)**: bảng `finding` có cột `service_id` (khóa ngoại tới `service`,
    `ON DELETE SET NULL`). Khi lưu, finding được nối với service theo (port, protocol)
    **trong cùng một host**. `Storage.load_run()` đọc lại nguyên một run (host → service →
    finding, trạng thái, scanner, host ngoài scope); `findings_for_run()` trả finding kèm
    `service`, nên tính lại fingerprint từ dữ liệu đọc ra cho đúng giá trị đã lưu.
  - Còn lại: finding của DB cũ (schema v1) không có thông tin này → `service_id` để NULL,
    không đoán. ~~`ScanRun.plan` (địa chỉ đã duyệt, danh sách loại trừ) chưa được lưu~~ (✅ G21).
  - Dẫn chứng: bảng `finding` không có cột `service_id`; `Storage.findings_for_run()` trả
    `Finding.service = None`.
  - Hậu quả: không biết lỗi nằm ở cổng nào; diff giữa các lần quét thiếu dữ liệu.
  - Sửa: thêm `finding.service_id REFERENCES service(id)` và đọc lại đầy đủ.

## Mức 2 — Thiếu so với công cụ thật

- [x] **G6. Chỉ quét 1.000 cổng phổ biến** (mặc định của nmap).
  Sửa: scan profile `quick` / `full` (`-p-`); quét định kỳ dùng `full`.
  - ✅ **Đã sửa (`feat/scan-profiles`)**: 4 profile dựng sẵn — `quick` (100 cổng), `standard`
    (1.000 cổng, mặc định, giữ đúng hành vi cũ `-sV -T4`), `full` (`-p -` cả 65.535 cổng +
    traceroute, timeout 4 giờ, mỗi host tối đa 1 giờ), `gentle` (`-T2`, tối đa 50 gói/giây cho
    mạng yếu). Mỗi run lưu **tên profile và toàn bộ thông số** (schema DB v6): kết quả của
    `quick` và `full` không so được với nhau — quét thật trên 127.0.0.1 cho thấy `quick` bỏ sót
    cổng 903 mà `standard` thấy.
  - Còn lại: chưa quét UDP (`-sU` chậm và cần quyền root; danh sách cổng chỉ nhận TCP). Chưa có
    bước "tìm cổng nhanh rồi mới `-sV` trên cổng mở" như masscan/naabu → nmap.
- [x] **G7. Cố định `-T4` và timeout 300s.**
  Sửa: cấu hình được tốc độ, timeout, rate limit (file config + cờ CLI).
  - ✅ **Đã sửa (`feat/scan-profiles`)**: file TOML (`--config`, bảng `[profiles.<tên>]`, kế thừa
    một profile dựng sẵn bằng `base`) và cờ CLI ghi đè từng thông số (`--ports`, `--top-ports`,
    `--timing`, `--max-rate`, `--host-timeout`, `--timeout`, `--[no-]traceroute`,
    `--assume-up`). Thứ tự ưu tiên: dựng sẵn < file cấu hình < cờ CLI. Mọi giá trị được kiểm
    **trước khi quét**: khóa lạ, sai kiểu, ngoài khoảng, ghi đè profile dựng sẵn → lỗi, exit 2;
    danh sách cổng chỉ nhận số / dải số nên không thể chèn thêm tuỳ chọn cho nmap (vd
    `-oN file`). nmap quá thời gian → giữ lại phần output đã in làm bằng chứng.
  - Còn lại: chưa tự giảm tốc khi mạng báo nghẽn (nmap đã tự làm một phần trong `-T`); chưa
    có khung giờ được phép quét (→ G21).
- [x] **G8. CVE khớp đúng phiên bản, bỏ qua CPE.**
  Sửa: khớp theo CPE + **dải phiên bản** (`versionStartIncluding`, `versionEndExcluding`…).
  - Thêm: nmap thật trả version kiểu `7.4p1 Debian 10+deb9u7`, không phải `7.4` → so khớp
    chính xác với seed **trượt ngay cả ví dụ OpenSSH 7.4**. `tests/data/nmap_sample.xml` đang
    dùng version "sạch" (`7.4`) nên test không bắt được. Cần chuẩn hóa version (tách upstream
    `7.4p1` khỏi hậu tố distro) và so sánh theo số, không theo chuỗi (`7.10` > `7.9`).
    Fixture test nên lấy từ output nmap thật.
  - Tên sản phẩm của nmap ≠ tên trong CPE (`Apache httpd` ↔ `apache:http_server`) — thêm lý
    do phải khớp theo CPE thay vì theo tên.
  - ✅ **Đã sửa (`feat/cve-matching`)**: `zues_scan/cve/` thành package. Dữ liệu CVE (seed và
    sau này cache NVD) dùng định dạng 2: mỗi CVE có danh sách `affects` y như `cpeMatch` của NVD
    (CPE + `versionStart/EndIncluding/Excluding`); seed được viết lại theo dữ liệu NVD thật.
    Khớp theo **vendor + product của CPE** (nmap không có CPE thì tra bảng tên sản phẩm nmap →
    CPE), có bảng alias vendor cho những chỗ nmap và NVD gọi khác nhau (`igor_sysoev` ↔ `f5`
    cho nginx, `vsftpd` ↔ `vsftpd_project`). Version được **tách ra** trước khi so:
    `7.4p1 Debian 10+deb9u7` → bản upstream `7.4`, patch level `p1`, dấu hiệu gói distro; so
    sánh **theo số** (`7.10 > 7.9`, `1.0rc1 < 1.0`, `1.0.2k < 1.0.2l`). Fixture mới mô phỏng
    đúng chuỗi version nmap trả cho gói Debian/Ubuntu. File CVE định dạng cũ hoặc hỏng → lỗi
    rõ ràng, exit 2.
  - Còn lại: cấu hình AND của NVD ("… chạy trên Debian 9") không được kiểm, chỉ dùng mục của
    chính sản phẩm (quét cổng không thấy chắc hệ điều hành). Bảng alias vendor / tên sản phẩm
    viết tay, chỉ gồm các trường hợp đã gặp. Một số kiểu version lạ (`1.0.0rc1` so với `1.0`,
    chữ cái đơn kiểu `1.0b2` là beta hay bản sửa?) có thể so sai. Seed chỉ có 4 CVE (→ G9).
- [x] **G9. Dữ liệu CVE chỉ là seed 4 dòng.**
  Sửa: `NvdCveSource` đồng bộ NVD API 2.0 về cache local (có API key, tôn trọng rate limit);
  cân nhắc OSV, CISA KEV.
  - ✅ **Đã sửa (`feat/nvd-source`)**: `zues cve sync` tải CVE từ NVD API 2.0 về một file
    SQLite riêng (`zues-cve.db`: bảng `cve`, `cve_range` có index theo sản phẩm,
    `sync_state`). Chỉ dùng thư viện chuẩn (`urllib`). Mỗi trang 2.000 CVE; nghỉ 6 giây giữa
    hai request (1 giây nếu có API key, đọc từ biến môi trường `NVD_API_KEY`, không bao giờ
    nhận qua dòng lệnh); gặp 403 / 429 / 5xx thì chờ lâu dần rồi thử lại. Lần đầu tải hết,
    các lần sau chỉ hỏi những CVE **đổi từ lần sync trước** (`lastModStartDate`, chia cửa sổ
    ≤ 120 ngày). Chỉ ghi nhận "đã sync" khi mọi trang đã lưu: đứt mạng giữa chừng thì chạy lại.
    `--product cpe:2.3:a:openbsd:openssh` để chỉ tải một sản phẩm. CVE bị NVD reject thì bị xóa
    khỏi cache. `scan --cve-cache` khớp trên cache, **offline** (không lần quét nào gửi mục
    tiêu ra ngoài). Đã kiểm với NVD thật: 192 CVE của OpenSSH / nginx / vsftpd; OpenSSH
    `7.4p1 Debian 10+deb9u7` khớp 42 CVE, đều `tentative`.
  - Còn lại: tải toàn bộ NVD lần đầu (~300.000 CVE) mất khoảng 15–20 phút nếu không có API
    key. NVD đôi khi ghi dải theo bản phát hành mà bỏ patch level (vd OpenSSH `<= 9.8` trong
    khi bản vá là `9.8p1`) → ZuesScan theo đúng dữ liệu NVD nên có thể báo nhầm bản đã vá. Chưa
    dùng OSV (dữ liệu theo gói của từng hệ sinh thái / distro).
- [x] **G10. Không phân biệt "chắc chắn" và "có thể" bị lỗi** (backport của distro giữ nguyên
  số phiên bản). Sửa: thêm `Finding.confidence` (`tentative` / `confirmed`).
  - ✅ **Đã sửa (`feat/cve-matching`)**: `Finding.confidence` có 3 mức (theo thang của các
    scanner thương mại): `tentative` — suy ra từ version nhưng có lý do để nghi (gói của distro:
    Debian/Ubuntu/RHEL… thường vá bằng backport mà giữ nguyên số version; evidence nhắc kiểm
    security tracker của distro), `firm` — vendor + product + version upstream rõ ràng,
    `confirmed` — chỉ khi một bài kiểm thực sự chạm vào lỗi (dành cho plugin nuclei). Lưu trong
    cột `finding.confidence` (schema DB v7), hiện ở CLI và báo cáo HTML. Không nằm trong
    fingerprint.
  - ✅ `confirmed` đã có nguồn (`feat/plugin-nuclei`): template CVE của nuclei gửi đúng request
    khai thác (an toàn) và kiểm câu trả lời; nếu cùng CVE cũng khớp theo version, finding quan
    sát được giữ lại.
  - ✅ **Quét có đăng nhập (`feat/authenticated-scan`)**: với host có khai báo SSH key
    (`--credentials`), ZuesScan đọc gói đã cài (`dpkg-query`) và đối chiếu Debian Security
    Tracker (so version theo đúng thuật toán của dpkg). CVE mà gói đã cài **có bản vá** thì
    finding đoán theo banner cho CVE đó trên host bị **rút lại** (ghi chú trong run). An toàn:
    chỉ key (không mật khẩu), host key phải có sẵn trong file known_hosts riêng (không tin lần
    đầu), lệnh từ xa cố định, chỉ đọc, không sudo.
  - Còn lại: chỉ Debian (Ubuntu dùng dữ liệu riêng — USN/OVAL — chưa làm; RHEL cũng vậy). Chưa
    thử trên một máy Debian thật qua SSH (đã thử với dữ liệu tracker thật). Không đăng nhập thì
    vẫn là heuristic như trên.
- [x] **G11. Severity là nhãn gõ tay.** Sửa: lưu điểm + vector CVSS; cân nhắc EPSS để ưu tiên.
  - ✅ **Đã sửa (`feat/cve-priority`)**: mỗi finding mang **CVSS** (điểm + vector, ưu tiên điểm
    của NVD, v3.1 > v3.0 > v4.0 > v2), **CWE**, ngày vào **CISA KEV** (đã bị khai thác ngoài
    thực tế) và **EPSS** (xác suất bị khai thác trong 30 ngày, FIRST tính lại mỗi ngày) — lưu
    theo run (schema DB v8): run ghi lại điều nó biết lúc đó. `zues cve sync` tải thêm catalog
    KEV (từ mirror GitHub chính thức của CISA, vì www.cisa.gov chặn client tự động) và file EPSS
    hằng ngày (~410.000 CVE). **Thứ tự ưu tiên** (theo tinh thần SSVC / "KEV trước, rồi EPSS,
    rồi CVSS"): P1 có trong KEV; P2 EPSS ≥ 10 % hoặc CVSS ≥ 9; P3 EPSS ≥ 1 % hoặc CVSS ≥ 7;
    P4 còn lại. CLI và báo cáo sắp theo ưu tiên và nói lý do. Kiểm với dữ liệu thật: MySQL 8.0.37
    trên máy dev khớp 61 CVE, 2 cái P3 (EPSS ~1 %), còn lại P4.
  - Còn lại: ngưỡng EPSS / CVSS là lựa chọn của ZuesScan, chưa cấu hình được. Chưa tính bối
    cảnh tài sản (máy public hay nội bộ, quan trọng đến đâu) như SSVC đầy đủ. Cờ "dùng trong
    ransomware" của KEV mới chỉ hiện ở `cve show`. EPSS / KEV của run cũ không tự cập nhật.
- [x] **G12. Fingerprint có `title`.** Sửa câu chữ title là lỗi cũ thành "lỗi mới".
  Sửa: định danh theo asset + port + protocol + CVE/rule id (đổi schema fingerprint có version).
  - ✅ **Đã sửa (F8)**: fingerprint = băm của **ở đâu** (địa chỉ IP của máy, chỉ dùng tên khi
    không có IP; port; protocol) + **lỗi gì** (CVE; không có thì `rule_id` của bài kiểm; không
    có cả hai thì mới dùng title). Bỏ khỏi định danh: title, description, severity, evidence,
    product, **version** — máy nâng từ bản lỗi này lên bản lỗi khác vẫn là *cùng một lỗi còn
    mở*. Fingerprint tự ghi công thức của nó: `v2:<sha256>` (`FINGERPRINT_SCHEME`).
    `Finding` thêm `rule_id` (cột mới, schema DB v3) và `ip`. Orchestrator là **nơi duy nhất**
    đặt fingerprint, sau khi gộp host; hai tool báo cùng một lỗi trên cùng cổng → một finding.
    Quét theo tên và quét theo IP cho cùng fingerprint.
  - Còn lại (đã cân nhắc, ghi lại để làm sau):
    - Fingerprint cũ trong DB (công thức 1, không có tiền tố) **không được tính lại**: các
      dòng từ schema v1 không biết lỗi nằm ở cổng nào. Run trước F8 và sau F8 vì thế không so
      được với nhau bằng fingerprint; `feat/diff` phải bỏ qua cặp khác công thức.
    - Máy đổi IP (DHCP, cloud) → fingerprint đổi → lỗi cũ thành "mới". Công cụ thật giải
      bằng định danh tài sản bền hơn IP (agent UUID, MAC, tên máy). → D1 (kho tài sản).
    - ~~Nhiều website chung một IP (virtual host): lỗi của từng site sẽ cần tên host trong
      định danh~~ ✅ `feat/plugin-nuclei`: `rule_id` của nuclei có dạng `nuclei:<template>@<vhost>`.
    - Finding không có CVE lẫn `rule_id` vẫn định danh bằng title (đã chuẩn hóa hoa/thường
      và khoảng trắng) — plugin mới phải điền `rule_id`.
- [x] **G13. Không lưu bằng chứng** (`evidence` rỗng, XML nmap bị bỏ).
  Sửa: lưu output gốc của tool theo run; điền `evidence` cho finding.
  - ✅ **Đã sửa (F9)**: hợp đồng plugin đổi thành `scan(target) -> ScanResult` (danh sách
    `Asset` + `RawOutput`: output gốc của tool, đúng từng byte, kèm dòng lệnh đã chạy và
    stderr). Mỗi run lưu output vào bảng `scan_run_output` (schema DB v4): nén zlib, kèm
    kích thước và **SHA-256** của bản gốc; khi đọc ra thì kiểm lại mã băm, lệch → từ chối
    (bằng chứng đã bị sửa hoặc hỏng). Lần quét **thất bại** cũng giữ output nếu tool đã kịp in
    ra (XML hỏng, 0 host, không host nào trả lời). Lệnh mới `zues raw <run id>` lấy lại
    output (stdout chỉ có output, pipe được; hoặc `--out file`). Finding của bước CVE có
    `evidence`: cổng, product / version / CPE / banner scanner báo, khớp với mục nào của nguồn
    CVE, và ghi rõ là *suy luận theo phiên bản, chưa kiểm chứng bằng khai thác*.
  - Còn lại:
    - Output gốc chứa cả dữ liệu về host ngoài scope mà kết quả đã loại (cố ý: đó là ghi
      nhận tool đã thực sự làm gì) và có thể chứa banner nhạy cảm → file DB phải được bảo vệ
      như dữ liệu kiểm thử; chưa có mã hóa, chưa có chính sách xóa sau N ngày (→ Giai đoạn 3).
    - Chưa giới hạn kích thước output; quét `-p-` cả dải lớn có thể vài chục MB mỗi run.
    - Finding chưa trỏ tới *đoạn* cụ thể trong output gốc, chỉ mô tả bằng chữ.
    - Mã băm chống sửa nhầm / hỏng dữ liệu, **không** chống người có quyền ghi DB (họ sửa được
      cả mã băm). ✅ G21: mã băm output gốc nằm trong chuỗi audit; lưu mã băm đầu chuỗi ở nơi
      khác thì phát hiện được cả việc viết lại lịch sử.
- [x] **G14. `scan_run` không có trạng thái / lỗi / phiên bản tool.**
  Sửa: thêm `status`, `error`, `tool_version`.
  - ✅ **Đã sửa (F7)**: `scan_run` có `status` (`completed` / `partial` / `failed`, có ràng
    buộc `CHECK`), `error`, `zues_version`. Phiên bản tool nằm ở bảng riêng
    `scan_run_plugin` (mỗi scanner một dòng: `ran` / `skipped` / `failed` + `version`) vì
    một run sẽ có nhiều scanner; hợp đồng plugin thêm `version()`. Host ngoài scope bị loại
    được lưu vào `scan_run_out_of_scope`.
  - **Đổi hành vi**: lần quét thất bại (exit 4) nay **được lưu** thành một run `failed` kèm
    thông báo lỗi và stderr của tool, không có host nào. Lý do: khi quét theo lịch, "quét bị
    hỏng" mà không để lại gì thì trông y hệt "chưa ai quét". Run `failed` không thể bị đọc
    nhầm thành "đã quét, không thấy gì". Bị scope từ chối (exit 3) vẫn không tạo run.
  - Còn lại: ~~chưa có lệnh CLI xem danh sách run~~ (✅ M1: `zues runs`); ~~lần bị scope từ
    chối chưa để lại dấu vết~~ (✅ G21: sự kiện `refused` trong audit trail).
- [x] **G15. Thiếu index khóa ngoại, thiếu `ON DELETE CASCADE`, chưa có migration.**
  Sửa: index FK, cascade, bảng `schema_version` + migration đơn giản.
  - ✅ **Đã sửa (F7)**: mọi khóa ngoại có index và `ON DELETE CASCADE` (riêng
    `finding.service_id` là `SET NULL`); `Storage.delete_run()` xóa một run cùng mọi thứ bên
    dưới. Schema có số phiên bản (`SCHEMA_VERSION = 2`, bảng `schema_version`): mở DB là tự
    chạy các migration còn thiếu trong **một transaction** (hỏng giữa chừng → DB cũ nguyên
    vẹn), sau khi **sao lưu** DB cũ ra `<db>.v<N>.bak`, và kiểm `PRAGMA foreign_key_check`
    trước khi commit. DB do bản ZuesScan mới hơn ghi thì từ chối mở. CLI mở DB **trước** khi
    quét. Đã kiểm bằng cách migrate một DB v1 thật.
  - Còn lại: `service` chưa có ràng buộc `UNIQUE (asset_id, port, protocol)`; bản sao lưu
    không tự dọn.
- [x] **G16. `Asset.ip` không bao giờ được điền.** (sửa cùng G1) ✅ F5: plugin nmap điền từ
  `<address addrtype="ipv4|ipv6">`.
- [x] **G21. Không có dấu vết kiểm toán về uỷ quyền.** (từ Bài 3)
  - ✅ **Đã sửa (`feat/audit-trail`)**: mỗi run lưu **người chạy** (mặc định `user@host`,
    `--operator`), **engagement** (`--engagement` hoặc dòng `@engagement` trong file scope),
    **file scope** (đường dẫn + SHA-256 của đúng từng byte; nội dung được lưu một lần cho mỗi
    phiên bản, xem lại bằng `zues audit --scope <sha>`) và **kế hoạch quét đã duyệt** (địa
    chỉ, loại trừ) — schema DB v10. File scope có thể ghi **điều khoản của giấy phép**:
    `@expires 2026-12-31 +07:00` (hết hạn thì từ chối), `@window Mon-Fri 22:00-06:00 +07:00`
    (chỉ quét trong khung giờ, qua nửa đêm được). Bảng `audit_event` ghi **mọi lần quét, mọi
    lần bị từ chối (exit 3) và mọi lần xóa run** thành một **chuỗi băm SHA-256**: mỗi sự kiện
    băm cả nội dung của nó lẫn mã băm sự kiện trước; sự kiện quét chứa mã băm output gốc.
    `zues audit --verify` tính lại cả chuỗi và kiểm từng bằng chứng: sửa / xóa / đổi thứ tự
    một sự kiện, thay output gốc, hay xóa run mà không qua `zues delete` đều bị phát hiện.
    Ghi chuỗi lấy khóa ghi trước (`BEGIN IMMEDIATE`) và `prev_hash` là UNIQUE nên hai tiến
    trình không thể làm chuỗi rẽ nhánh. Đã kiểm với nmap thật.
  - Còn lại: người có quyền ghi DB vẫn dựng lại được *cả* chuỗi — phải lưu **mã băm đầu chuỗi**
    (in ra bởi `--verify`) ở nơi họ không sửa được (ticket, email cho khách hàng, máy chủ log);
    chưa có chữ ký số hay gửi tự động đi đâu. Người chạy lấy từ hệ điều hành, không có xác thực
    (→ web app có đăng nhập, GĐ 3). Khung giờ dùng độ lệch UTC cố định, không theo múi giờ có
    giờ mùa hè.
  - Dẫn chứng: `scan_run` chỉ lưu `target`, `started_at`, `finished_at`. Không biết lần quét
    đó dùng file scope nào (nội dung lúc đó ra sao), ai chạy, theo giấy phép / đợt kiểm thử
    nào. Scope cũng không có khung giờ được phép quét.
  - Hậu quả: khi bên bị quét hỏi "ai cho phép quét máy này lúc 2 giờ sáng", DB không trả lời
    được; sửa file scope sau khi quét là mất dấu.
  - Sửa: lưu vào `scan_run` mã băm SHA-256 + đường dẫn của file scope, người chạy, và một
    trường tham chiếu giấy phép (`--engagement`); cân nhắc khung giờ trong file scope.
- [x] **G22. Chưa hỗ trợ IPv6.** (từ F6)
  - ✅ **Đã sửa (`feat/ipv6`)**: tên miền được phân giải ra **cả IPv4 lẫn IPv6** (A + AAAA) và
    **mọi** địa chỉ, kể cả IPv6, phải nằm trong scope (không thì từ chối, nêu rõ địa chỉ).
    `--ipv4-only` để chỉ dùng IPv4 — lựa chọn này được ghi vào run. nmap không trộn được hai họ
    địa chỉ nên plugin chạy **một lượt mỗi họ** (`-6` cho IPv6), chia cả danh sách loại trừ;
    họ nào không host nào trả lời (thường gặp: có bản ghi AAAA nhưng máy quét không đi được
    IPv6) thì thành **ghi chú** của run, không làm hỏng cả lần quét, miễn họ kia có kết quả.
    Dải IPv6 lớn hơn /112 bị từ chối: một subnet /64 có 2^64 địa chỉ, không quét quét lần lượt
    được — host IPv6 được tìm qua DNS. Run có thêm `notes` (schema DB v9); `zues raw
    --index` chọn một trong nhiều output. Đã kiểm với nmap thật: `localhost` → 127.0.0.1 và ::1.
  - Còn lại: chưa tìm host IPv6 bằng cách khác ngoài DNS (vd Neighbor Discovery trong LAN).
  - Dẫn chứng: `resolve_ipv4()` chỉ hỏi bản ghi A; plugin nmap không truyền `-6` (nmap
    không trộn được IPv4 và IPv6 trong một lần chạy).
  - Hậu quả: tên miền có cả AAAA thì phần IPv6 không được kiểm tra scope lẫn quét — an toàn
    (không đụng tới địa chỉ chưa duyệt) nhưng bỏ sót bề mặt tấn công. Target là địa chỉ
    IPv6 qua được scope nhưng nmap báo lỗi (exit 4).
  - Sửa: phân giải cả AAAA, kiểm scope như IPv4, chạy nmap riêng với `-6` cho nhóm IPv6.

- [ ] **G23. Dịch vụ chạy nền: những giới hạn còn lại.** (từ `feat/worker-queue`)
  - ✅ Đã có: `service.toml` (chỉ target được khai mới quét được; token chỉ lưu SHA-256; cấu
    hình sai thì không khởi động), hàng đợi Redis + RQ, worker chạy đúng đường quét của CLI,
    scheduler có khoá mỗi vòng, cảnh báo webhook (fix giả, xuất hiện lại, finding mới ≥ P2).
    Đã chạy thật: Redis 7.4 (Docker) + `scheduler --once` + `worker --burst` trên Windows quét
    nmap thật 127.0.0.1, hai job → hai run trong DB; webhook nhận payload qua HTTP thật.
  - ✅ Cảnh báo không mất nữa (`feat/alert-outbox`, schema 16): bảng `alert_outbox`, cảnh báo của
    run ghi trong cùng transaction với run; worker gửi ngay, scheduler gửi lại mỗi vòng (backoff
    1 phút → 1 giờ, `Retry-After`, bỏ cuộc sau 24 giờ / ngay với 4xx vô vọng hay redirect); có
    lease để hai tiến trình không gửi trùng; ký HMAC-SHA256 có timestamp; Settings → Alerts (trạng
    thái, gửi lại, gửi thử). Đã thử thật: webhook trả 503 → cảnh báo chờ → `scheduler --once` gửi
    lại, cùng `X-ZuesScan-Delivery`, bên nhận xác minh chữ ký. Còn lại:
    - Gửi *ít nhất một lần*: POST thành công mà chưa kịp đánh dấu "đã gửi" (tiến trình chết đúng
      lúc) thì gửi lại — bên nhận phải bỏ trùng theo `X-ZuesScan-Delivery`.
    - Chỉ có webhook: chưa email / PagerDuty / Teams gốc; chưa định tuyến theo mức (P1 tới kênh
      trực, P3 tới kênh thường) hay theo target.
    - ✅ Đổi secret có giai đoạn chuyển tiếp (`feat/webhook-secret-rotation`): `previous_secret`
      → mỗi cảnh báo mang hai chữ ký, bên nhận khớp một là đủ. Còn lại: bên nhận phải dùng cách
      kiểm nhiều chữ ký (README); chưa có nhắc bỏ `previous_secret` khi quá lâu.
    - ✅ Outbox tự dọn (`feat/outbox-retention`): `keep_days` (mặc định 90, tối thiểu 7 — dài
      hơn cửa sổ chống lặp), scheduler xoá mỗi giờ. Còn lại: các bảng khác giữ mãi (run, output
      gốc, audit) — đó là dữ liệu của đợt kiểm thử, xoá bằng `zues delete`; chưa có hạn giữ
      tự động theo engagement.
  - **Worker trên Windows chạy job trong chính tiến trình của nó** (không có `fork()`): một job
    làm sập tiến trình thì sập cả worker; giới hạn thời gian bằng luồng hẹn giờ không ngắt được
    một lời gọi C đang chặn. Đỡ được phần lớn vì plugin tự đặt timeout cho nmap/nuclei (tiến trình
    con bị giết). Thực tế: chạy worker trên Linux (container — `chore/docker`), mỗi job một
    tiến trình con, có supervisor khởi động lại.
  - ✅ Job lỗi có người được báo (`feat/alert-outbox`): quét hỏng `failed_scans` lần liền (và khi
    chạy lại được), quét không bắt đầu được (scope từ chối, vd uỷ quyền hết hạn), job hỏng không
    lưu được run (callback `on_failure` của RQ — cả khi RQ dọn job của worker đã chết). Còn lại:
    worker bị giết cứng (OOM) chỉ được báo khi RQ dọn registry của nó, có thể chậm vài phút.
  - ✅ Lịch cron + lịch không trôi (`feat/cron-schedule`): `cron = "0 2 * * sat Asia/Ho_Chi_Minh"`
    (múi giờ IANA có giờ mùa hè, hoặc độ lệch), tối thiểu 5 phút; mốc lịch lưu trong Redis nên
    `every` không trôi theo thời gian chờ hàng đợi; lỡ nhiều mốc thì bù một lần. Còn lại: Redis mất
    dữ liệu thì mốc rơi về lịch sử quét (có thể lệch một lần); chưa có "không quét vào ngày lễ".
  - ✅ Web (`feat/web`): API + dashboard dùng token.
  - ✅ Phiên & đăng nhập sai (`feat/web-sessions`, schema 15): cookie chỉ chứa khoá ngẫu nhiên của
    một **phiên do server giữ** (DB lưu SHA-256 của khoá + token đã mở phiên); hết khi đăng xuất
    (xoá ở server), 30 phút không dùng (lần tự làm mới của trang không tính), 8 giờ, token bị thu
    hồi / cấp lại, hoặc admin kết thúc ở Settings → Sessions. 10 token sai / 15 phút từ một địa chỉ
    → khoá 15 phút (429, kể cả token đúng), log + audit `auth`; đếm trong Redis, Redis hỏng thì
    trong tiến trình. Đã thử bằng Chrome headless trên dịch vụ thật. Còn lại:
    - Khoá **theo địa chỉ**: mọi người sau cùng một NAT / proxy bị khoá chung khi một người đoán
      sai. Thực tế: khoá theo địa chỉ + theo token (khi biết là token nào), CAPTCHA / bằng chứng
      công việc trước khi khoá cứng, danh sách địa chỉ tin cậy.
    - ✅ Lần bị khoá còn được cảnh báo qua webhook (outbox, một lần mỗi giờ mỗi địa chỉ).
    - ✅ Token có hạn dùng và xoay vòng được (`feat/token-expiry`, schema 17): mặc định 90 ngày,
      cảnh báo một tuần trước hạn, Rotate thu hồi giá trị cũ và phiên của nó ngay. Còn lại: chưa
      có phạm vi theo target (một token chỉ thấy / quét một target) — đi cùng phân quyền theo
      target bên dưới.
    - Chưa có xác thực hai lớp (TOTP / WebAuthn) hay đăng nhập qua SSO (OIDC) cho người dùng.
    - **Không tự làm TLS**: `zues web` mặc định chỉ nghe 127.0.0.1; ra mạng thì phải đặt sau
      reverse proxy có TLS (cookie tự bật `Secure` khi proxy báo `X-Forwarded-Proto: https`).
    - ✅ Quyền theo target (`feat/target-permissions`, schema 19, D13): token viewer / operator
      giới hạn vào target theo mẫu tên; ngoài phạm vi trả 404; audit chỉ cho token không giới hạn.
      Còn lại: host thuộc **hai** khách hàng (dải trùng nhau) thì finding của nó hiện với cả hai;
      cảnh báo webhook vẫn chung cho cả dịch vụ (chưa định tuyến theo khách hàng); chưa có
      "engagement" làm đơn vị quyền ngoài tên target; run quét bằng CLI không có tên target.
    - ✅ Phân trang + so sánh run (`feat/web-compare`): runs theo khoá (`before`), findings theo
      trang (`X-Total-Count`); `/runs/{id}/diff`, trang Compare, tool MCP `compare_runs`. Còn lại:
      findings sắp theo mức ưu tiên tính trong Python nên mỗi trang vẫn đọc cả danh sách (ổn tới
      vài chục nghìn finding; lớn hơn thì cần cột ưu tiên được lưu và đánh index).
    - Không có Swagger UI (`/docs` tải script từ CDN, trái CSP); schema OpenAPI vẫn ở
      `/api/v1/openapi.json` để nhập vào công cụ khác.
    - ✅ SQLite dùng WAL (`feat/sqlite-wal`): đọc dài không chặn lưu run (có test đối chứng: chế độ
      cũ thì lưu hỏng "database is locked"); chờ ghi tối đa 15 giây; bản backup vẫn là một file;
      dịch vụ bật lại WAL khi khởi động (vd sau khôi phục); `zues doctor` báo. Còn lại: người ghi
      vẫn lần lượt từng người — nhiều worker lưu run lớn cùng lúc, hoặc nhiều máy dùng chung một
      DB, thì cần PostgreSQL (repository đã tách SQL sau các phương thức của `Storage`). WAL không
      chạy trên ổ mạng.
  - ✅ Webhook được ký (HMAC-SHA256 + timestamp, `[notify] secret` / `ZUES_WEBHOOK_SECRET`). URL
    webhook vẫn là bí mật (log chỉ ghi tên host) — đừng commit `service.toml` hay `.env` thật.

- [ ] **G24. nuclei và subfinder chạy thật: những gì đã kiểm và còn thiếu.** (Bài 8)
  - ✅ **`feat/tool-runtime`** (đo bằng nuclei 3.11.1 + templates 10.5.2, subfinder 2.17.0 thật):
    - check (nuclei) lỗi hoặc hết giờ **không** còn làm hỏng cả lần quét: kết quả nmap giữ lại,
      run `partial`; hết giờ thì giữ finding đã thấy. Trước đây profile `standard` (900 s) với
      vài web server là đủ để mất trắng kết quả.
    - dịch vụ không phải web được kiểm (`ip:port`, chỉ template mạng); templates ghim chạy offline
      với cấu hình riêng mỗi lần; chỉ template có chữ ký (`-dut`); bỏ mức `info`; phiên bản
      templates ghi vào run.
    - finding trùng (nuclei + theo phiên bản) được **gộp**: trước đây bản quan sát thắng nhưng
      đánh rơi ngày KEV / CVSS của NVD (Apache 2.4.49 bị xếp P2 thay vì P1).
    - discovery có giới hạn tên, phân giải song song, lọc wildcard DNS, ghi chú gộp (trước đây
      25.514 tên = 25.514 lượt DNS tuần tự và 25.514 dòng ghi chú).
  - ✅ **`feat/lab-nuclei`**: lab có Apache khai thác được → nuclei xác nhận CVE-2021-41773 và
    Terrapin; CI chạy cả lab với nuclei. `check_rate` tách khỏi `max_rate` (trước đây giới hạn
    hợp với nuclei làm nmap quét đủ cổng chậm ~30 lần).
  - Còn lại:
    - ✅ **Job lab của CI chập chờn** (c94ab6b, rồi cdc0006): bước "nuclei confirmed what the
      versions suggested" hỏng rồi qua với cùng code. Đã tìm ra (`fix/nuclei-network-timeouts`):
      bóp CPU của sshd trong lab còn 0,1 lõi, nuclei với `-timeout 10 -retries 1` lỡ Terrapin
      4/10 lần (sshd không bỏ kết nối nào: là bắt tay chậm, không phải MaxStartups); với
      `-timeout 30 -retries 3` cho lần chạy template mạng: 5/5. Lỗi của sản phẩm, không riêng
      CI — máy chủ SSH / TLS bận ngoài thực tế cũng chậm như vậy. Job lab giờ ghi rõ kiểm tra nào
      hỏng và in bảng finding thành annotation (xem được không cần đăng nhập).
      Còn lại: **hỏng lại một lần** (c581d77, 2026-11-25): lần quét lại của demo không thấy
      Terrapin (`gone`); chạy lại ở máy và lần CI kế tiếp (7e4afc3, cùng code quét) đều thấy.
      Sau 11 lần xanh liên tiếp — tỉ lệ thấp nhưng chưa bằng 0. Job lab giờ in thêm ghi chú
      nuclei và lượt template mạng (số dòng, stderr) của từng run khi hỏng, để lần sau phân biệt
      bắt tay chậm với check hỏng.
    - ✅ **Kênh ngoài (OAST) với máy chủ interactsh tự dựng** (`feat/interactsh-self-hosted`,
      D18): `ZUES_INTERACTSH_SERVER` / `ZUES_INTERACTSH_TOKEN`; máy chủ công cộng và địa chỉ IP
      bị từ chối; token chỉ nằm trong file cấu hình của từng lần chạy (không trên dòng lệnh,
      không trong bằng chứng, plugin bên thứ ba không thấy); máy chủ được hỏi trước khi quét,
      không trả lời thì `-ni` + ghi chú; `zues doctor`. Kiểm thật: interactsh-server 1.4.1 +
      nuclei 3.11.1, app Log4Shell → CVE-2021-44228 `confirmed` qua callback DNS. **Lỗi tìm ra
      khi thử thật**: khi interactsh hỏng (sai token, không tới được), nuclei vẫn chạy tiếp và in
      `"error": "interactsh client not initialized"` + `matcher-status: false`; dòng có `error`
      (kể cả bị từ chối kết nối với template thường) trước đây được tính là "đã thử, không
      khớp" — giờ không tính, và được ghi chú. Còn lại:
      - máy chủ chỉ được kiểm từ phía máy quét: mục tiêu có tới được nó không (DNS của mục tiêu
        dẫn tới máy chủ, tường lửa cho ra) thì không biết trước — "không có callback" được ghi
        đúng như vậy, không phải "không lỗi";
      - lab và CI chưa có máy chủ interactsh + app Log4Shell (đã thử thật bằng tay, các bước ở
        README); `-iserver` qua HTTPS dùng kiểm tra chứng chỉ của nuclei (chưa thử với chứng chỉ
        nội bộ tự ký);
      - interactsh chỉ giữ tương tác trong bộ nhớ đệm 60 s của nuclei (`-interactions-eviction`):
        callback tới rất muộn (hàng đợi, job chạy sau) bị bỏ lỡ.
    - ✅ **Dịch vụ web mà nmap gọi sai tên** (`feat/web-detect`): app Spring Boot (Log4Shell)
      trả 404 JSON nên nmap gọi cổng 8080 là `nagios-nsca`, và httpx / nuclei chỉ coi là web dịch
      vụ có `http` trong tên → chỉ template mạng chạy trên nó. Giờ httpx hỏi mọi cổng TCP mở (trừ
      giao thức nmap nhận rõ không phải web và cổng máy in 9100–9107); trả lời HTTP thì nuclei
      kiểm như web, run ghi rõ cổng nào. Kiểm thật: `zues scan --check httpx --check nuclei` trên
      app Log4Shell → CVE-2021-44228 `confirmed`. Còn lại: httpx phải chạy trước nuclei (không
      tự thêm); danh sách "không phải web" là danh sách tay; nmap nhận sai một dịch vụ thành
      `ssh` / `mysql`… thì vẫn bỏ qua.
    - ✅ Bằng chứng của nuclei được che trước khi lưu (`feat/evidence-redaction`,
      `zues_scan/redact.py`): header đăng nhập / phiên, mẫu bí mật (mật khẩu, JWT, khoá AWS, PEM,
      hash shadow, mật khẩu trong URL), thân response cắt còn 2 KB. Còn lại: che theo mẫu là cố
      gắng tốt nhất — bí mật có hình dạng lạ vẫn lọt; chưa có tuỳ chọn "giữ nguyên" cho cuộc kiểm
      thử cần bằng chứng đầy đủ (nên đi kèm mã hoá DB); output của các tool khác (nmap script,
      httpx) chưa qua bước che (hiện không chứa request / response).
    - ✅ "Đã thử, không khớp" (`feat/nuclei-tried`, schema 22): CVE chỉ suy ra từ phiên bản được
      thử lại bằng template nuclei của chính nó (`-id … -ms`); không khớp → `Finding.tried`
      (run và kiểm kê; lần sau không thử thì giữ lần thử cuối, xác nhận thì xoá). Độ tin cậy giữ
      nguyên (đúng: CVE-2021-41773 cần `Require all granted`). Template cần interactsh không
      bao giờ được ghi là "đã thử" (dưới `-ni` nuclei vẫn báo không khớp — đã kiểm thật với
      CVE-2021-44228). Thử thật: nuclei 3.11.1 + templates 10.5.2. Còn lại: gửi lại request
      của template mà lượt chính đã gửi (một lần nữa cho vài CVE); chỉ CVE có template mang
      đúng tên `CVE-….yaml`; chưa lọc / xếp hạng finding theo "đã thử" trên dashboard.
    - Templates mới ra hằng ngày: bản ghim cần cập nhật định kỳ (dựng lại image). Template tự
      viết phải được ký (`nuclei -sign`) mới chạy dưới `-dut`.
    - `zues tools install`: bản macOS (amd64, arm64) có trong lock nhưng chưa được chạy thử
      trên một máy Mac thật (Windows và Linux đã thử). Chưa có bản Windows arm64 của nuclei.
    - Rate mặc định 50 req/s: một web server ~4 phút; dải lớn cần `max_rate` cao hơn hoặc
      `timeout` dài hơn trong profile.
    - subfinder chỉ thụ động (không brute-force DNS); không có API key thì ít nguồn; lọc wildcard
      chỉ dựa trên một tên ngẫu nhiên (zone có nhiều mức wildcard có thể lọt).

- [ ] **G25. Plugin của bên thứ ba chạy với toàn quyền của ZuesScan.** (từ `feat/plugin-registry`)
  - ✅ Đã có: registry + entry points; gói hỏng bị bỏ qua và báo; không được trùng tên plugin dựng
    sẵn; mỗi plugin khai `activity`, scope đặt trần `@activity` (mặc định `scan`), vượt trần bị
    từ chối trước khi gửi gì và ghi vào audit; plugin khai thấp hơn spec của chính nó bị từ chối;
    bộ kiểm tra hợp đồng `zues_scan.plugins.contract`.
  - ✅ Dịch vụ chỉ nạp plugin được ghim (`feat/plugin-allowlist`, D14): `[[plugins]]` trong
    service.toml hoặc `ZUES_PLUGINS`, mỗi mục là gói + phiên bản + SHA-256 các file trong RECORD
    (`zues plugins --pin NAME` in ra); kiểm từ file trên đĩa **trước khi import** — chưa ghim, sai
    phiên bản, một file bị sửa / xoá, entry point trỏ sang module của gói khác, cài editable → không
    nạp, code không chạy, `zues doctor` báo. `activity` cho cổng scope là mức người vận hành ghi;
    plugin khai cao hơn thì bị từ chối. Thử thật trong container Linux: chưa ghim → target dừng với
    lý do; ghim → quét, finding `confirmed`; sửa một byte → bị từ chối, đoạn code thêm vào không chạy.
  - Còn lại:
    - ✅ Plugin của gói khác chạy ở **tiến trình riêng** (`feat/plugin-process`, D15): mỗi lời gọi
      (đọc spec, probe, scan / check / discover) là một tiến trình con nhận JSON, môi trường sạch
      (không `ZUES_*`: DB, Redis, secret webhook, token), thư mục tạm rỗng làm HOME, không có DB /
      CVE cache / credentials SSH / API key subfinder; giới hạn thời gian (giết cả nhóm tiến trình,
      kể cả công cụ nó khởi động), trả lời ≤ 128 MiB; kiểm lại pin trong tiến trình con trước khi
      import; câu trả lời được đọc từng trường như dữ liệu không tin cậy. Code của gói không bao giờ
      chạy trong tiến trình của ZuesScan. Thử thật: test trên Windows + Linux (container sạch), job
      quét với exposed-git trong container Linux → finding `confirmed`.
    - ✅ Trên Linux, tiến trình con **tự giới hạn bằng Landlock** trước khi import plugin
      (`feat/plugin-landlock`, D16, không cần root): nó và mọi chương trình nó chạy chỉ đọc được hệ
      thống (`/usr`, `/lib`…, vài file cần thiết của `/etc` — không cả `/etc`), Python, gói của
      ZuesScan, gói của plugin, công cụ của ZuesScan, templates / wordlist của lần quét; chỉ ghi
      được thư mục tạm của nó. Database, cấu hình dịch vụ, credentials, CVE cache nằm ngoài → "permission
      denied"; Landlock còn chặn ptrace nên `/proc/<pid của dịch vụ>/environ` cũng không đọc được.
      Kernel có Landlock mà giới hạn hỏng thì lời gọi hỏng, không chạy tiếp mà không giới hạn.
      `zues doctor` báo. Thử thật: test trên Linux (container, Landlock v1) — đọc DB, ghi cạnh DB,
      đọc environ của dịch vụ, `cat` DB từ chương trình con đều bị từ chối; job exposed-git vẫn tìm
      ra finding `confirmed`.
    - Còn lại của tiến trình riêng:
      - ✅ **Redis của dịch vụ** (`feat/queue-hardening`, D19). Đã thử thật: từ một tiến trình có
        môi trường sạch trong container worker (đúng chỗ plugin chạy), Redis không mật khẩu nhận
        một job `subprocess.getoutput(...)` và worker chạy nó — **ngoài sandbox**, với quyền của
        worker. Giờ Redis có mật khẩu (compose tự sinh, file trong volume `secrets`, plugin không
        đọc được: môi trường sạch + Landlock) → `NOAUTH`; và job là JSON, worker chỉ chạy job quét
        của ZuesScan → kể cả người có mật khẩu cũng không chạy được hàm khác (pickle hay JSON đều
        bị từ chối, không chạy). Thử thật trên stack compose và lab.
      - **Mạng vẫn không bị giới hạn theo địa chỉ**: plugin kết nối được tới mọi nơi worker tới
        được — máy ngoài scope, dịch vụ nội bộ khác, Internet (rò dữ liệu quét ra ngoài). Không có
        cách giới hạn theo địa chỉ mà không cần quyền: Landlock ABI 4 chỉ theo cổng TCP (và Docker
        Desktop có Landlock v1); seccomp không đọc được địa chỉ của `connect()`; network namespace
        không root bị seccomp mặc định của Docker chặn; eBPF cgroup cần root. Thực tế: worker trong
        mạng riêng chỉ có đường tới dải được quét + egress firewall / NetworkPolicy chặn phần còn
        lại (web và Redis vẫn cần tới được: Redis có mật khẩu, web cần token).
      - Windows, macOS, kernel không có Landlock: không giới hạn file (doctor cảnh báo) — chạy dịch vụ
        trong container Linux của nó.
      - `no_new_privs` (Landlock cần): chương trình plugin chạy không nhận được file capability (vd
        quyền raw socket của nmap trong image) — plugin của gói khác không dùng được SYN scan;
        nmap dựng sẵn không bị ảnh hưởng (chạy trong tiến trình của ZuesScan).
      - Chưa giới hạn bộ nhớ / CPU (RLIMIT_AS làm hỏng công cụ viết bằng Go như nuclei — cần cgroup).
      - Mỗi lời gọi tốn một lần khởi động Python (~0,3–1 s): không đáng kể so với một lần quét.
    - Phụ thuộc của plugin (gói khác nó import) và file `.pth` của gói khác không nằm trong pin:
      ghim chúng khi dựng image (`pip install --require-hashes`, như `tools.lock` với công cụ).
    - Kiểm pin lúc nạp, không theo dõi sau đó: một file bị sửa giữa lúc kiểm và lúc import (cửa sổ
      rất ngắn) không bị bắt — người sửa được site-packages của dịch vụ thì đã có quyền của nó.
    - `zues scan` ở dòng lệnh mặc định vẫn nạp mọi plugin đã cài (cài là đã quyết định); đặt
      `ZUES_PLUGINS` để áp cùng chính sách.

- [ ] **G26. AI agent qua MCP: giới hạn còn lại.** (từ `feat/mcp`)
  - ✅ Đã có: `zues mcp` (stdio, client của web API), 12 tool; xếp hàng quét / ghi quyết định
    cần người xác nhận (elicitation, không phải tham số của tool); không có tool chấp nhận rủi ro;
    chỉ target đã cấu hình; dữ liệu quét được làm sạch và đánh dấu không tin cậy; audit dưới tên
    token. Đã thử bằng client MCP thật qua stdio trên lab (từ chối → không quét; đồng ý → run
    #5 ghi `operator = lab-admin`; `8.8.8.8` → từ chối, không hỏi ai).
  - Còn lại:
    - **Việc hỏi người dùng là của client.** Một client tự động trả lời "đồng ý" thì xác nhận
      chỉ còn là hình thức; lớp bảo vệ thật vẫn là vai trò của token, danh sách target, scope,
      giới hạn quét và audit. ✅ `feat/scan-limits` (D17): token có `scans_per_hour` (quá thì
      429 + `Retry-After`), và một target không bao giờ bị quét chồng (đang chờ / đang chạy →
      409, cả với scheduler). ✅ `feat/scanner-role`: vai trò `scanner` (giữa `viewer` và
      `operator`) — đọc + xin quét target của nó, có `targets` và `scans_per_hour` như operator,
      **không** ghi quyết định về finding, không sửa cài đặt: token cho agent nên là `scanner`
      (chỉ đọc thì `viewer`, mặc định của `zues token` / `zues user add`). Kiểm: test API + dashboard
      bằng Chrome (scanner có "Scan now", không có form quyết định). Còn: chọn vai trò vẫn là việc
      của người cấp token — ZuesScan không biết token nào do agent dùng.
    - Giới hạn đếm **số yêu cầu** quét, không đếm thời gian hay gói tin: vài lần quét `full` vẫn
      nặng — tải lên target do profile quyết định (`max_rate`, `timeout`). Một job kẹt ở trạng
      thái đang chạy (worker bị giết đột ngột) chặn target tới khi RQ dọn nó (hết `job_timeout`
      của job đó).
    - Chỉ stdio: chưa có MCP qua HTTP (Streamable HTTP + OAuth) để agent ở máy khác dùng trực
      tiếp dịch vụ. Hiện agent ở máy khác dùng `ZUES_URL` qua HTTPS (reverse proxy).
    - Token nằm trong biến môi trường / file cấu hình của client MCP (không commit; nên dùng phạm
      vi `local` / `user` của Claude Code, không phải `project`).
    - Làm sạch chuỗi chống được ký tự điều khiển và độ dài, **không** chống được nội dung thao
      túng viết bằng chữ thường; model vẫn phải coi đó là dữ liệu (đã nói trong mô tả tool).

- [ ] **G27. dnsx: giới hạn còn lại.** (từ `feat/dnsx`)
  - ✅ Đã có: dò tên bằng wordlist, mức `scan`, tốc độ theo `check_rate`, nhận ra wildcard DNS
    bằng hai tên ngẫu nhiên, resolver của hệ thống; hết giờ thì giữ tên đã xác nhận. Đã thử
    thật với CoreDNS riêng (vùng thường và vùng wildcard).
  - Còn lại:
    - ✅ **Windows** (`feat/dnsx-windows-resolvers`): dnsx hỏi DNS server mà Windows dùng
      (`GetNetworkParams` qua ctypes, IPv4), không còn rơi về resolver công khai; hệ thống không
      nêu resolver nào thì run ghi chú; `zues doctor` hiện danh sách. Thử thật trên Windows 11
      (`-r 172.11.0.1,8.8.8.8,8.8.4.4`). Còn lại: DNS server IPv6 của Windows bị bỏ qua (thường
      chỉ là `fec0::` giữ chỗ đã lỗi thời); chưa có tham số `resolvers` riêng cho một target;
      DNS theo từng card mạng / theo hậu tố (NRPT, VPN split DNS) không được xét — Windows chọn
      server theo tên, dnsx hỏi cả danh sách.
    - Resolver IPv6 trong resolv.conf bị bỏ qua (chưa thử cú pháp `-r` của dnsx với IPv6).
    - Wildcard chỉ nhận ra khi mọi địa chỉ của tên nằm trong địa chỉ của hai tên ngẫu nhiên:
      wildcard trả về địa chỉ xoay vòng từ một dải lớn (CDN) có thể lọt qua — cổng scope vẫn
      kiểm lại từng tên trước khi quét.
    - Chưa dò đệ quy (tên dưới tên vừa tìm, vd `*.dev.example.com`) và chưa sinh biến thể
      (`dev1`, `dev-api`… từ tên đã biết).

- [ ] **G28. naabu: giới hạn còn lại.** (từ `feat/naabu`)
  - ✅ Đã có: nmap `-sn` → naabu connect scan trên host sống → nmap `-sV` chỉ trên cổng mở;
    host sống không mở cổng vẫn được giữ; hết giờ / nhận diện dịch vụ hỏng → giữ cổng, run
    `partial`. Thử thật trên lab: cùng kết quả với nmap.
  - Còn lại:
    - Chỉ connect scan: SYN scan của naabu cần libpcap + root (image không có libpcap; worker
      chạy uid 10001). Trên LAN nhanh, nmap vẫn nhanh hơn (đo trong README).
    - Không có nmap thì không dò host được: mọi cổng của mọi địa chỉ đều bị thử (có ghi chú).
    - Chỉ TCP; top N cổng của profile được làm tròn lên danh sách 100 / 1000 / full của naabu.
    - Chưa đo trên Internet (đường trễ cao, nhiều host) — nơi naabu đáng lẽ có lợi; cần một
      mục tiêu có giấy phép để đo.

- [ ] **G29. httpx: giới hạn còn lại.** (từ `feat/httpx`)
  - ✅ Đã có: URL / trạng thái / tiêu đề / server / công nghệ trên mỗi dịch vụ web, lưu trong
    database (schema 13), hiện ở CLI, bản đồ, API, MCP; công nghệ có phiên bản → bước CVE, gộp
    với finding của nmap. Thử thật trên lab (Apache, nginx) và trong job lab của CI.
  - Còn lại:
    - ✅ **Virtual host** (`feat/httpx-vhosts`, schema 21): mỗi dịch vụ web còn được hỏi dưới mỗi
      tên của host (`Host:` = tên, kết nối vẫn tới IP đã duyệt — dòng `tên,ip:cổng` của httpx,
      tên không được phân giải lại); trang theo tên lưu ở `Service.vhosts`, công nghệ vào bước
      CVE. Thử thật với httpx 1.12.0: HTTP, HTTPS, IPv6, mỗi tên đúng một request. Còn lại:
      - **SNI** vẫn là địa chỉ (cờ `-sni` của httpx là một tên cho cả lần chạy): máy chủ chọn
        trang chỉ theo SNI (HAProxy / Traefik định tuyến TLS theo SNI, CDN) trả trang mặc định.
        Sửa: một lần chạy httpx cho mỗi tên với `-sni`, hoặc client HTTP riêng.
      - Chỉ các tên đã biết (tên target, tên tìm được bằng DNS); chưa đoán vhost (brute-force
        Host header bằng wordlist — mức `active`, dễ bị coi là tấn công) hay đọc tên từ chứng
        chỉ TLS (SAN).
      - Nhiều tên × nhiều cổng có thể nhiều request: giới hạn 200 cặp mỗi lần, theo `check_rate`.
      - Cách của nuclei (một lần chạy mỗi tên, có `-sni`) gửi đúng SNI nhưng chậm hơn; httpx giữ
        một lần chạy cho cả target.
    - Chỉ trang gốc `/`, không theo redirect: ứng dụng ở `/app/` hay sau một redirect sang HTTPS
      có thể không được nhận diện đầy đủ.
    - `TECH_NAMES` là danh sách tay (~20 tên); công nghệ khác hiện ra nhưng không đối chiếu CVE.
      Phiên bản Wappalyzer đoán từ trang (vd đường dẫn file JS) có thể sai — finding vẫn chỉ là
      "firm", không phải "confirmed".
    - Bảng điều khiển web chưa có trang kiểm kê web riêng (tìm theo công nghệ: "mọi máy chạy
      PHP 7"); dữ liệu đã có trong API.

- [ ] **G30. Cấu hình qua dashboard: giới hạn còn lại.** (từ `feat/managed-config`)
  - ✅ Đã có: vai trò `admin`; scope / target / token lưu trong database, kiểm như lúc quét
    trước khi lưu, audit `config` trong chuỗi băm, có hiệu lực ngay; `service.toml` chỉ đọc và
    thắng khi trùng tên; `zues user add` tạo admin đầu tiên / lấy lại quyền.
  - ✅ Sửa (`fix/scheduler-reload`): scheduler chạy liên tục từng chỉ đọc cấu hình một lần lúc
    khởi động, nên target thêm trên dashboard **không bao giờ được quét định kỳ** cho tới khi khởi
    động lại. Nay đọc lại mỗi vòng; có test cho cả target thêm giữa chừng và cấu hình hỏng.
  - Còn lại:
    - **Admin mở rộng được giấy phép quét** (theo yêu cầu của chủ dự án: sửa được cả scope trên
      giao diện). Lớp bảo vệ: số người giữ token admin, audit trail, và ✅ cảnh báo webhook cho
      **mọi** thay đổi scope / target / token (`feat/config-alerts`, cùng transaction với audit).
      ✅ Duyệt hai người cho thay đổi scope (`feat/scope-approval`, schema 18, D12) khi bật
      `scope_approval`. Còn lại: tắt mặc định (một admin không có người thứ hai); target và token
      admin mới không cần duyệt (target vẫn bị scope giới hạn; token admin mới không duyệt được
      thay đổi của người tạo ra nó); chưa có số người duyệt > 2 hay nhóm người duyệt riêng.
    - ✅ Token có hạn dùng + Rotate (`feat/token-expiry`). Còn lại: chưa có đăng nhập SSO /
      OIDC; chưa ép đổi token admin theo chu kỳ (hạn dùng là trần, không phải chính sách riêng).
    - Target trên dashboard chưa dùng được credentials SSH hay file profile riêng (cố ý: không
      trỏ tới file trên máy chủ); chỉ các profile dựng sẵn.
    - ✅ Lịch sử scope trên giao diện (`feat/scope-history`): trang sửa scope có mục *History*
      (từ audit trail: mọi phiên bản, đề xuất, quyết định), *Compare* với bản hiện tại, *Load into
      editor* rồi lưu lại = khôi phục (vẫn qua kiểm tra, audit, duyệt hai người nếu bật). API
      `GET /admin/scopes/{name}/history`, `/versions/{sha256}`. ✅ `feat/config-history`: scope
      đã xoá có mục *Deleted scopes* trong Settings → *History / restore* (bản cuối vào trang soạn
      scope mới cùng tên; lưu = tạo lại, qua kiểm tra / audit / duyệt); target có *History* (thiết
      lập nào đổi, ai, lúc nào); API lịch sử cho target và token (không có giá trị hay hash của
      token). Kiểm bằng test API + Chrome. Còn lại: lịch sử token chỉ qua API (chưa có trên trang);
      lịch sử là audit trail — xoá database là mất (như mọi bằng chứng khác, xem sao lưu).

## Mức 3 — Hoàn thiện sản phẩm / portfolio

- [x] **G17. Chưa có CI.** Sửa: GitHub Actions chạy pytest + ruff + mypy cho mọi PR. (F1, `chore/ci`)
- [x] **G18. Chỉ in ra màn hình.** Sửa: xuất báo cáo JSON / HTML / SARIF.
  - ✅ **Phần HTML (M1, `feat/report-html`)**: `zues report --html` sinh một file HTML tự
    chứa (bản đồ Cytoscape.js + bảng finding / host + thông tin run), mở offline. Dữ liệu quét
    (banner, tên sản phẩm) do máy bị quét tự khai nên có thể độc: JSON được escape để không thoát
    được khỏi thẻ `<script>`, script của trang chỉ ghi text (không `innerHTML`), CSP chỉ cho
    chạy script / style có SHA-256 đã liệt kê và `default-src 'none'` (trang không gọi mạng được).
    `zues runs` liệt kê các run.
  - ✅ **JSON / SARIF (`feat/report-json-sarif`)**: `--json` xuất đúng dữ liệu của báo cáo;
    `--sarif` xuất SARIF 2.1.0 (chuẩn OASIS, DefectDojo đọc được): mỗi CVE / bài kiểm là một
    *rule* (link NVD, CWE, `security-severity`), mỗi finding là một *result* có mức, `rank` theo
    CVSS, vị trí `tcp://host:port`, fingerprint của ZuesScan trong `partialFingerprints` (để công
    cụ khác nhận ra cùng một lỗi qua các lần quét), và ưu tiên / độ tin cậy / EPSS / KEV / trạng
    thái vòng đời. ~~Báo cáo chưa so sánh hai run~~ (✅ `feat/diff`: mục "Changes").
  - Còn lại: SARIF mới được kiểm theo cấu trúc trong test, chưa chạy validator theo JSON schema
    chính thức, cũng chưa thử import vào DefectDojo thật. Mỗi báo cáo
    nặng ~470 KB vì nhúng nguyên Cytoscape.js. Host được nhóm theo /24 (/64) vì từ ngoài không
    thấy subnet mask thật.
- [x] **G19. Dùng `print`, chưa có logging.** Sửa: module `logging`, cờ `--verbose`.
  - ✅ **Đã sửa (`feat/logging`)**: mỗi module ghi log qua `logging.getLogger(__name__)` (cây
    `zues`). Mặc định chỉ hiện cảnh báo; `-v` tiến trình, `-vv` chi tiết (lệnh nmap đầy đủ,
    từng request NVD); `--log-file` luôn ghi đủ mức debug; `--log-format json` mỗi dòng một object
    JSON (có trường `event`, `run_id`…) cho hệ thống gom log. Không bao giờ ghi API key (nó nằm
    trong header, không trong URL) và không ghi output gốc của scanner (đã có trong DB, có băm).
    `print` vẫn dùng cho phần trả lời người dùng ở CLI — đó là giao diện, không phải log.
- [x] **G20. Chưa có Docker, README chưa có demo.** Sửa: Dockerfile, ảnh/GIF demo, mục
  "Known limitations" trong README trỏ về file này.
  - ✅ **Demo (`feat/lab`)**: README mở đầu bằng ảnh dashboard + bản đồ chụp từ lab thật
    (headless Chrome), lab chạy bằng `sh lab/up.sh` + `sh lab/demo.sh`, mục "Giới hạn đã biết"
    trỏ về file này.
  - ✅ **Docker (`chore/docker`)**: `Dockerfile` (image gốc ghim digest, gói Python ghim phiên bản
    + mã băm, user không phải root, nmap chỉ có `cap_net_raw`), `compose.yaml` (Redis có AOF,
    web / worker / scheduler, FS chỉ đọc, `cap_drop: ALL`, chỉ worker có `NET_RAW`, healthcheck,
    web chỉ ở 127.0.0.1), `zues backup` (backup trực tuyến + kiểm tra + SHA-256 + mã băm đầu
    chuỗi audit, xoay vòng, `--verify`). CI build image và quét thật một container bằng SYN scan
    + traceroute với user thường chỉ giữ `NET_RAW`. Đã chạy thử cả stack: scheduler → worker →
    API → backup trong lúc chạy.
  - ✅ **`chore/docker-tools`**: nuclei, subfinder, nuclei-templates trong image, ghim phiên bản
    + SHA-256 từ file checksums chính thức (nay là `zues_scan/data/tools.lock`,
    `python -m zues_scan.tools update`; cũng dùng cho `zues tools install`); CI
    kiểm phiên bản trong image khớp lock. Lưu ý: file checksums lấy cùng nơi với file nhị phân
    (tin lần đầu); ProjectDiscovery chưa ký release bằng cosign/GPG để kiểm độc lập.
  - ✅ **`chore/release`**: workflow phát hành quét image bằng Trivy, xuất SBOM + provenance, ký
    cosign keyless, image amd64 + arm64 — chạy khi có tag đầu tiên. Trivy chỉ báo cáo (không chặn
    phát hành) vì image mang binary Go của bên thứ ba.
  - Còn lại (trước `chore/release`): chưa **quét lỗ hổng chính image** (Trivy/Grype trong CI)
    và chưa **ký image** (cosign) / xuất SBOM; digest image gốc phải tự cập nhật (Dependabot /
    Renovate); backup chưa tự chạy theo lịch và chưa mã hoá — thực tế: job định kỳ + đẩy bản mã
    hoá (age/GPG) ra kho ngoài (S3 có object lock).
