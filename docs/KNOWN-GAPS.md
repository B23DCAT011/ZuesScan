# Điểm yếu đã biết & kế hoạch nâng cấp — ReconKit

Danh sách các chỗ ReconKit **chưa đạt chuẩn sản phẩm thật**, kèm dẫn chứng trong code và
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
  - ✅ **Đã sửa (`feat/cve-matching`)**: `reconkit/cve/` thành package. Dữ liệu CVE (seed và
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
  - ✅ **Đã sửa (`feat/nvd-source`)**: `reconkit cve sync` tải CVE từ NVD API 2.0 về một file
    SQLite riêng (`reconkit-cve.db`: bảng `cve`, `cve_range` có index theo sản phẩm,
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
    khi bản vá là `9.8p1`) → ReconKit theo đúng dữ liệu NVD nên có thể báo nhầm bản đã vá. Chưa
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
    (`--credentials`), ReconKit đọc gói đã cài (`dpkg-query`) và đối chiếu Debian Security
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
    theo run (schema DB v8): run ghi lại điều nó biết lúc đó. `reconkit cve sync` tải thêm catalog
    KEV (từ mirror GitHub chính thức của CISA, vì www.cisa.gov chặn client tự động) và file EPSS
    hằng ngày (~410.000 CVE). **Thứ tự ưu tiên** (theo tinh thần SSVC / "KEV trước, rồi EPSS,
    rồi CVSS"): P1 có trong KEV; P2 EPSS ≥ 10 % hoặc CVSS ≥ 9; P3 EPSS ≥ 1 % hoặc CVSS ≥ 7;
    P4 còn lại. CLI và báo cáo sắp theo ưu tiên và nói lý do. Kiểm với dữ liệu thật: MySQL 8.0.37
    trên máy dev khớp 61 CVE, 2 cái P3 (EPSS ~1 %), còn lại P4.
  - Còn lại: ngưỡng EPSS / CVSS là lựa chọn của ReconKit, chưa cấu hình được. Chưa tính bối
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
    ra (XML hỏng, 0 host, không host nào trả lời). Lệnh mới `reconkit raw <run id>` lấy lại
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
    buộc `CHECK`), `error`, `reconkit_version`. Phiên bản tool nằm ở bảng riêng
    `scan_run_plugin` (mỗi scanner một dòng: `ran` / `skipped` / `failed` + `version`) vì
    một run sẽ có nhiều scanner; hợp đồng plugin thêm `version()`. Host ngoài scope bị loại
    được lưu vào `scan_run_out_of_scope`.
  - **Đổi hành vi**: lần quét thất bại (exit 4) nay **được lưu** thành một run `failed` kèm
    thông báo lỗi và stderr của tool, không có host nào. Lý do: khi quét theo lịch, "quét bị
    hỏng" mà không để lại gì thì trông y hệt "chưa ai quét". Run `failed` không thể bị đọc
    nhầm thành "đã quét, không thấy gì". Bị scope từ chối (exit 3) vẫn không tạo run.
  - Còn lại: ~~chưa có lệnh CLI xem danh sách run~~ (✅ M1: `reconkit runs`); ~~lần bị scope từ
    chối chưa để lại dấu vết~~ (✅ G21: sự kiện `refused` trong audit trail).
- [x] **G15. Thiếu index khóa ngoại, thiếu `ON DELETE CASCADE`, chưa có migration.**
  Sửa: index FK, cascade, bảng `schema_version` + migration đơn giản.
  - ✅ **Đã sửa (F7)**: mọi khóa ngoại có index và `ON DELETE CASCADE` (riêng
    `finding.service_id` là `SET NULL`); `Storage.delete_run()` xóa một run cùng mọi thứ bên
    dưới. Schema có số phiên bản (`SCHEMA_VERSION = 2`, bảng `schema_version`): mở DB là tự
    chạy các migration còn thiếu trong **một transaction** (hỏng giữa chừng → DB cũ nguyên
    vẹn), sau khi **sao lưu** DB cũ ra `<db>.v<N>.bak`, và kiểm `PRAGMA foreign_key_check`
    trước khi commit. DB do bản ReconKit mới hơn ghi thì từ chối mở. CLI mở DB **trước** khi
    quét. Đã kiểm bằng cách migrate một DB v1 thật.
  - Còn lại: `service` chưa có ràng buộc `UNIQUE (asset_id, port, protocol)`; bản sao lưu
    không tự dọn.
- [x] **G16. `Asset.ip` không bao giờ được điền.** (sửa cùng G1) ✅ F5: plugin nmap điền từ
  `<address addrtype="ipv4|ipv6">`.
- [x] **G21. Không có dấu vết kiểm toán về uỷ quyền.** (từ Bài 3)
  - ✅ **Đã sửa (`feat/audit-trail`)**: mỗi run lưu **người chạy** (mặc định `user@host`,
    `--operator`), **engagement** (`--engagement` hoặc dòng `@engagement` trong file scope),
    **file scope** (đường dẫn + SHA-256 của đúng từng byte; nội dung được lưu một lần cho mỗi
    phiên bản, xem lại bằng `reconkit audit --scope <sha>`) và **kế hoạch quét đã duyệt** (địa
    chỉ, loại trừ) — schema DB v10. File scope có thể ghi **điều khoản của giấy phép**:
    `@expires 2026-12-31 +07:00` (hết hạn thì từ chối), `@window Mon-Fri 22:00-06:00 +07:00`
    (chỉ quét trong khung giờ, qua nửa đêm được). Bảng `audit_event` ghi **mọi lần quét, mọi
    lần bị từ chối (exit 3) và mọi lần xóa run** thành một **chuỗi băm SHA-256**: mỗi sự kiện
    băm cả nội dung của nó lẫn mã băm sự kiện trước; sự kiện quét chứa mã băm output gốc.
    `reconkit audit --verify` tính lại cả chuỗi và kiểm từng bằng chứng: sửa / xóa / đổi thứ tự
    một sự kiện, thay output gốc, hay xóa run mà không qua `reconkit delete` đều bị phát hiện.
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
    được — host IPv6 được tìm qua DNS. Run có thêm `notes` (schema DB v9); `reconkit raw
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
  - **Cảnh báo gửi không được thì mất** (chỉ ghi log). Thực tế: bảng *outbox* trong DB + gửi
    lại có backoff, đánh dấu đã gửi; hoặc đẩy cảnh báo thành job riêng trong hàng đợi có retry.
  - **Worker trên Windows chạy job trong chính tiến trình của nó** (không có `fork()`): một job
    làm sập tiến trình thì sập cả worker; giới hạn thời gian bằng luồng hẹn giờ không ngắt được
    một lời gọi C đang chặn. Đỡ được phần lớn vì plugin tự đặt timeout cho nmap/nuclei (tiến trình
    con bị giết). Thực tế: chạy worker trên Linux (container — `chore/docker`), mỗi job một
    tiến trình con, có supervisor khởi động lại.
  - Job lỗi chỉ nằm trong *failed registry* của RQ (30 ngày), chưa có ai được báo. Sẽ hiện trên
    web (`feat/web`); thực tế còn cần cảnh báo "lần quét định kỳ thất bại N lần liền".
  - Lịch chỉ có dạng "mỗi N phút / giờ / ngày", chưa có cron (vd "2 giờ sáng thứ Bảy") — kết
    hợp được với khung giờ `@window` của scope. Lịch tính từ lần quét trước nên trôi dần.
  - ✅ Web (`feat/web`): API + dashboard dùng token. Còn lại ở phần web:
    - **Không giới hạn số lần đăng nhập sai** (chỉ ghi log cảnh báo kèm IP). Token 256 bit nên
      đoán mò không khả thi, nhưng thực tế vẫn nên có rate limit / khoá tạm ở reverse proxy
      hoặc trong app, và cảnh báo khi một IP thử sai liên tục.
    - **Cookie chứa chính token** (HttpOnly, SameSite=Strict, 8 giờ): đăng xuất chỉ xoá cookie
      ở trình duyệt; muốn vô hiệu hoá thật thì gỡ token khỏi `service.toml`. Thực tế: phiên
      phía server (id ngẫu nhiên trong Redis, hết hạn khi không dùng, thu hồi được từng phiên).
    - **Không tự làm TLS**: `reconkit web` mặc định chỉ nghe 127.0.0.1; ra mạng thì phải đặt sau
      reverse proxy có TLS (cookie tự bật `Secure` khi proxy báo `X-Forwarded-Proto: https`).
    - Phân quyền mới có hai vai trò cho toàn bộ dịch vụ; chưa có quyền theo từng target /
      engagement (vd khách hàng A chỉ thấy target của A).
    - Danh sách finding / run chưa phân trang (giới hạn số dòng); chưa có trang so sánh hai run
      trên web (đã có ở CLI `reconkit diff` và mục "Changes" của báo cáo).
    - Không có Swagger UI (`/docs` tải script từ CDN, trái CSP); schema OpenAPI vẫn ở
      `/api/v1/openapi.json` để nhập vào công cụ khác.
    - SQLite dùng chế độ journal mặc định: web đọc trong lúc worker ghi thì phải chờ nhau (tối đa
      5 giây). Nhiều worker + web đông người dùng: bật WAL hoặc chuyển sang PostgreSQL.
  - Webhook chưa ký (HMAC) nên bên nhận không xác minh được nguồn; URL webhook là bí mật — đừng
    commit `service.toml` thật.

## Mức 3 — Hoàn thiện sản phẩm / portfolio

- [x] **G17. Chưa có CI.** Sửa: GitHub Actions chạy pytest + ruff + mypy cho mọi PR. (F1, `chore/ci`)
- [x] **G18. Chỉ in ra màn hình.** Sửa: xuất báo cáo JSON / HTML / SARIF.
  - ✅ **Phần HTML (M1, `feat/report-html`)**: `reconkit report --html` sinh một file HTML tự
    chứa (bản đồ Cytoscape.js + bảng finding / host + thông tin run), mở offline. Dữ liệu quét
    (banner, tên sản phẩm) do máy bị quét tự khai nên có thể độc: JSON được escape để không thoát
    được khỏi thẻ `<script>`, script của trang chỉ ghi text (không `innerHTML`), CSP chỉ cho
    chạy script / style có SHA-256 đã liệt kê và `default-src 'none'` (trang không gọi mạng được).
    `reconkit runs` liệt kê các run.
  - ✅ **JSON / SARIF (`feat/report-json-sarif`)**: `--json` xuất đúng dữ liệu của báo cáo;
    `--sarif` xuất SARIF 2.1.0 (chuẩn OASIS, DefectDojo đọc được): mỗi CVE / bài kiểm là một
    *rule* (link NVD, CWE, `security-severity`), mỗi finding là một *result* có mức, `rank` theo
    CVSS, vị trí `tcp://host:port`, fingerprint của ReconKit trong `partialFingerprints` (để công
    cụ khác nhận ra cùng một lỗi qua các lần quét), và ưu tiên / độ tin cậy / EPSS / KEV / trạng
    thái vòng đời. ~~Báo cáo chưa so sánh hai run~~ (✅ `feat/diff`: mục "Changes").
  - Còn lại: SARIF mới được kiểm theo cấu trúc trong test, chưa chạy validator theo JSON schema
    chính thức, cũng chưa thử import vào DefectDojo thật. Mỗi báo cáo
    nặng ~470 KB vì nhúng nguyên Cytoscape.js. Host được nhóm theo /24 (/64) vì từ ngoài không
    thấy subnet mask thật.
- [x] **G19. Dùng `print`, chưa có logging.** Sửa: module `logging`, cờ `--verbose`.
  - ✅ **Đã sửa (`feat/logging`)**: mỗi module ghi log qua `logging.getLogger(__name__)` (cây
    `reconkit`). Mặc định chỉ hiện cảnh báo; `-v` tiến trình, `-vv` chi tiết (lệnh nmap đầy đủ,
    từng request NVD); `--log-file` luôn ghi đủ mức debug; `--log-format json` mỗi dòng một object
    JSON (có trường `event`, `run_id`…) cho hệ thống gom log. Không bao giờ ghi API key (nó nằm
    trong header, không trong URL) và không ghi output gốc của scanner (đã có trong DB, có băm).
    `print` vẫn dùng cho phần trả lời người dùng ở CLI — đó là giao diện, không phải log.
- [ ] **G20. Chưa có Docker, README chưa có demo.** Sửa: Dockerfile, ảnh/GIF demo, mục
  "Known limitations" trong README trỏ về file này.
