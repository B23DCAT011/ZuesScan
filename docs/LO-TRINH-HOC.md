# Lộ trình học — ReconKit

Học song song với làm: mỗi bài gắn với một phần code. Mỗi bài có 3 phần — **thuật ngữ**,
**thực tế người ta làm thế nào**, **ReconKit có theo không** — và kết luận được ghi thành
việc cần làm trong [`TASKS.md`](../TASKS.md) / [`KNOWN-GAPS.md`](KNOWN-GAPS.md).

Ghi chú thiết kế ban đầu: [`GHI-CHU.md`](../GHI-CHU.md).

| Bài | Chủ đề | Gắn với code | Trạng thái |
|---|---|---|---|
| 1 | Recon: quét cổng & nhận diện dịch vụ | `plugins/nmap.py`, `Service` | ✅ 2026-10-28 |
| — | Phân tích lỗi Mức 1: G1 CIDR, G4 scope/DNS, G2, G3, G5 | orchestrator, scope, cli, storage | ✅ 2026-10-28 |
| 2 | CVE, CPE, CVSS, NVD, KEV, EPSS | `cve.py`, `cve_seed.json` | ✅ 2026-10-28 |
| 3 | Scope & pháp lý: Rules of Engagement, xin phép quét, luật VN | `scope.py` | ✅ 2026-11-11 |
| 4 | Vòng đời finding: mới / còn mở / đã vá / tái xuất hiện | fingerprint, `feat/diff` | ✅ 2026-11-16 |
| 5 | Kiến trúc: pipeline, plugin, repository, transaction, migration | orchestrator, storage | ✅ 2026-11-22 |
| 6 | Công cụ thật (OpenVAS, Nessus, nuclei, DefectDojo) so với ReconKit | toàn dự án | ✅ 2026-11-22 |
| 7 | Từ công cụ thành dịch vụ: hàng đợi, web an toàn, container, lab cô lập | `server/`, Docker, `lab/` | ✅ 2026-11-23 |
| 8 | nuclei & subfinder ngoài đời thật: templates, chữ ký, OAST, wildcard DNS | `plugins/nuclei.py`, `plugins/subfinder.py` | ✅ 2026-11-23 |
| 9 | Cho AI dùng công cụ bảo mật: MCP, xác nhận của con người, prompt injection | `mcp_server.py` | ✅ 2026-11-23 |

---

## Bài 1 — Recon: quét cổng & nhận diện dịch vụ

- **Attack surface**: mọi chỗ kẻ tấn công chạm được. ReconKit = lập bản đồ attack surface và
  theo dõi nó thay đổi.
- **Passive** (tra nguồn công khai, vd subfinder) vs **active** (gửi gói tin, vd nmap → bắt buộc
  có scope).
- Trạng thái cổng: `open` / `closed` (máy trả lời, không có gì nghe) / `filtered` (firewall chặn).
- `-sV` = gửi probe, so câu trả lời với cơ sở mẫu để **đoán** product/version; **banner** là chuỗi
  dịch vụ tự gửi ra.
- Thực tế: quét cổng nhanh (masscan/naabu) rồi mới `-sV` trên cổng mở; quét đủ 65.535 cổng
  (`-p-`) — nmap mặc định chỉ 1.000 cổng; không tin tuyệt đối version (backport); tốc độ quét là
  thông số thỏa thuận với khách hàng.

## Phân tích lỗi Mức 1 (chi tiết trong KNOWN-GAPS.md)

- **CIDR** `10.0.0.0/24` = 256 địa chỉ. Đơn vị chuẩn trong scanner là **một máy (IP)**, không
  phải target. Gộp cả dải thành 1 asset → không biết lỗi ở máy nào, hai lỗi ở hai máy trùng
  fingerprint (G1).
- **DNS**: một tên → nhiều IP, IP đổi được, tên của mình ≠ máy của mình (CDN, SaaS).
  **TOCTOU**: kiểm tra một lúc, dùng một lúc khác. Đúng: phân giải 1 lần, kiểm mọi IP, quét
  bằng IP. Denylist phải kiểm **chồng lấn** (`overlaps`), không phải **nằm trong**
  (`subnet_of`). **Defense in depth**: kiểm trước, trong và sau khi quét (G4).
- **Fail loud vs fail silent**: công cụ bảo mật tệ nhất là báo "0 lỗi" khi thực ra chưa quét (G2).
- **Cây exception**: `except RuntimeError` không bắt `CalledProcessError` / `TimeoutExpired`.
  Bọc lỗi tại ranh giới (plugin) thành một loại lỗi của mình (G3).
- **Khóa ngoại**: finding phải trỏ tới service, nếu không đọc lại từ DB sẽ mất "lỗi ở cổng nào" (G5).
- Bài học chung: công cụ bảo mật được đánh giá trước hết ở chỗ **có nói thật không**.

## Bài 2 — CVE, CPE, CVSS, NVD, KEV, EPSS

- **CVE** = mã lỗ hổng; **CWE** = loại lỗi (vd CWE-22 path traversal); **CPE** = tên chuẩn phần
  mềm `cpe:2.3:a:vendor:product:version:…`; **CVSS** = điểm 0–10 + vector; **NVD** (NIST) làm giàu
  CVE bằng CPE/CVSS/CWE; **KEV** (CISA) = đã bị khai thác thật; **EPSS** (FIRST) = xác suất bị
  khai thác trong 30 ngày.
- CVSS đo **mức nghiêm trọng nếu bị khai thác**, không đo **khả năng bị khai thác** → ưu tiên
  KEV → EPSS → CVSS.
- NVD ghi **dải phiên bản** trên CPE (`versionEndIncluding: 7.7`), không ghi từng version. So
  version theo số (`7.10` > `7.9`), không theo chuỗi.
- nmap thật trả `7.4p1 Debian 10+deb9u7` → phải chuẩn hóa. **Backport**: distro vá nhưng giữ số
  version → quét từ xa chỉ là đoán (`confidence: tentative`); quét có đăng nhập mới chính xác.
- Thực tế: đồng bộ NVD về cache local (rate limit, offline, tái lập kết quả), không hỏi NVD mỗi
  lần quét; không phụ thuộc một nguồn (NVD tồn đọng từ 2024). **OSV** mạnh cho thư viện mã nguồn mở.

## Bài 3 — Scope & pháp lý

> Ghi chú học tập, không phải tư vấn pháp lý. Luật thay đổi: trước khi quét thật cho một tổ
> chức, đọc văn bản gốc và hỏi người có chuyên môn pháp lý.

**Thuật ngữ**

- **Authorization (uỷ quyền)**: sự cho phép **bằng văn bản** của người **có quyền** với hệ
  thống. Đây là ranh giới duy nhất giữa pentest và tấn công — kỹ thuật thì giống hệt nhau.
- **Scope**: danh sách cụ thể được phép đụng vào (IP, dải, domain) và **không** được đụng vào
  (out-of-scope). Trong ReconKit: file `--scope`, dòng `!` là deny.
- **Rules of Engagement (RoE)**: "luật chơi" của một đợt kiểm thử — scope, khung giờ được quét,
  kỹ thuật bị cấm (DoS, social engineering…), giới hạn tốc độ, đầu mối liên lạc khi có sự cố,
  cách xử lý dữ liệu nhạy cảm lỡ nhìn thấy.
- **Bug bounty / VDP**: chương trình công khai cho phép người ngoài tìm lỗi, kèm scope và
  **safe harbor** (cam kết không kiện nếu làm đúng luật chơi). Không có chương trình = không
  có phép, kể cả khi "chỉ muốn báo lỗi giúp".

**Thực tế người ta làm thế nào**

- Không có giấy thì không quét. Người ký phải là **chủ thật** của hệ thống: nhân viên IT
  không tự cho phép được; khách hàng thuê cloud/hosting không cho phép thay nhà cung cấp
  được (mỗi cloud có chính sách pentest riêng); một domain trỏ về CDN/SaaS thì IP đó là của
  bên thứ ba.
- Scope ghi bằng **IP/dải cụ thể**, và kiểm tra lại lúc quét: tên miền có thể đổi IP giữa lúc
  ký và lúc quét (đây chính là G4 phần DNS → F6).
- Mọi lần quét đều để lại **dấu vết kiểm toán**: ai quét, lúc nào, từ IP nào, vào đâu, theo
  giấy phép nào. Khi bên kia báo sự cố, đây là thứ chứng minh mình làm đúng phạm vi.
- Quét cổng **chưa** phải là xâm nhập, nhưng **không vì thế mà hợp pháp**: nó là bước chuẩn
  bị của tấn công, gây cảnh báo ở bên bị quét, có thể vi phạm điều khoản của nhà mạng/cloud,
  và quét mạnh có thể làm treo thiết bị yếu (khi đó là gây rối loạn hoạt động, không còn là
  "chỉ nhìn"). Nơi luyện tập hợp pháp: máy của mình, lab ảo (Metasploitable, DVWA),
  `scanme.nmap.org` (theo đúng điều kiện họ ghi), HackTheBox / TryHackMe.

**Luật Việt Nam (các văn bản cần biết tên)**

- **Bộ luật Hình sự 2015 (sửa đổi 2017), Điều 285–290** — nhóm tội phạm công nghệ thông tin:
  285 (sản xuất, mua bán công cụ, phần mềm để dùng vào mục đích trái pháp luật), 286 (phát
  tán chương trình gây hại), 287 (cản trở, gây rối loạn hoạt động mạng), 288 (đưa hoặc sử
  dụng trái phép thông tin mạng), **289 (xâm nhập trái phép vào mạng máy tính, mạng viễn
  thông hoặc phương tiện điện tử của người khác)**, 290 (dùng mạng để chiếm đoạt tài sản).
- Điều 289 khoản 1 (theo Nghị quyết 80/2021/NQ-UBTVQH15 giải thích): cố ý **vượt qua cảnh
  báo, mã truy cập, tường lửa, sử dụng quyền quản trị của người khác hoặc bằng phương thức
  khác** để xâm nhập trái phép. Từ khoá là *trái phép* — có uỷ quyền hợp lệ thì không còn
  yếu tố này.
- **Luật An ninh mạng 2025 (116/2025/QH15)**, hiệu lực 01/7/2026, thay cho cả Luật An toàn
  thông tin mạng 2015 và Luật An ninh mạng 2018; các hành vi bị nghiêm cấm nằm ở Điều 7.
  (Tài liệu cũ hơn giữa 2026 vẫn dẫn hai luật cũ.)
- Mức nhẹ hơn hình sự là xử phạt hành chính (nghị định về xử phạt trong lĩnh vực viễn thông,
  công nghệ thông tin). Ở nước khác: CFAA (Mỹ), Computer Misuse Act (Anh) — cùng nguyên tắc
  "không có phép = phạm luật".

**ReconKit có theo không**

| Thực tế yêu cầu | ReconKit hiện tại |
|---|---|
| Không quét khi chưa khai báo phạm vi | ✅ `--scope` bắt buộc; ngoài allowlist → từ chối, exit 3 |
| Có danh sách loại trừ, lỗi thì nghiêng về an toàn | ✅ deny `!`, dải chồng lấn deny bị từ chối, dòng sai → dừng (F2) |
| Kiểm tra IP thật, không chỉ tên | ✅ F6: phân giải một lần, kiểm mọi IP, quét bằng IP |
| Kiểm lại từng host trong kết quả | ✅ F6: host ngoài scope bị loại và được ghi lại |
| Giới hạn tốc độ / khung giờ theo RoE | ❌ cố định `-T4` (G7); chưa có khung giờ (G21) |
| Dấu vết kiểm toán: ai, lúc nào, theo giấy phép nào | ❌ `scan_run` chỉ có target + thời gian → **G21** |
| Nhắc người dùng về trách nhiệm pháp lý | ⚠️ chỉ có một dòng cảnh báo trong README |

Kết luận: file scope của ReconKit là **cái khoá kỹ thuật**, không phải **giấy phép**. Công cụ
chỉ biết "người dùng khai là được phép"; trách nhiệm có giấy thật vẫn ở người chạy. Việc của
công cụ là làm cho quét nhầm thật khó (F2, F6) và để lại bằng chứng đã làm đúng (G21).

## Bài 4 — Vòng đời finding

**Thuật ngữ**

- **Finding** = một lần *quan sát thấy* một vấn đề. **Vulnerability (lỗi)** = bản thân vấn đề,
  tồn tại qua nhiều lần quét. Quét 30 đêm thấy 30 finding nhưng chỉ có **một** lỗi. Việc nối 30
  quan sát đó thành một lỗi gọi là **deduplication / correlation**.
- **Định danh (identity)** của một lỗi: tập trường trả lời câu "đây có phải *cùng* lỗi lần
  trước không?". **Fingerprint** = băm của định danh, để so nhanh.
- **Trạng thái** thường gặp: *new* (lần đầu thấy) → *active / open* (vẫn thấy) → *fixed*
  (không còn thấy) → *resurfaced / reopened* (đã fixed rồi thấy lại). Ngoài luồng chính:
  *false positive* (công cụ báo sai), *risk accepted* (biết nhưng chấp nhận, phải có lý do và
  hạn xem lại), *mitigated* (chưa vá nhưng đã chặn bằng cách khác, vd firewall).
- **first seen / last seen**: lần đầu và lần cuối quan sát thấy. Từ đó tính **tuổi của lỗi** và
  **MTTR** (mean time to remediate — thời gian trung bình để vá).
- **SLA vá lỗi**: hạn vá theo mức độ, vd critical 7 ngày, high 30 ngày. Lỗi quá hạn là thứ
  báo cáo quản lý quan tâm nhất.
- **Fix giả (fake fix)**: ticket đã đóng "đã sửa" nhưng lần quét sau vẫn thấy đúng lỗi đó.
- **Regression**: lỗi đã vá thật rồi quay lại (rollback, dựng lại máy từ image cũ).

**Thực tế người ta làm thế nào**

- Định danh = **ở đâu + lỗi gì**, không bao giờ gồm câu chữ. Nessus / Tenable: máy + plugin ID +
  port + protocol. DefectDojo: `hash_code` băm từ một danh sách trường cấu hình được theo
  từng loại scanner. Lý do: title, mô tả, điểm CVSS đều bị sửa theo thời gian; nếu chúng nằm
  trong định danh thì mỗi lần cập nhật dữ liệu là mọi lỗi cũ "biến mất" và "xuất hiện mới".
- **Phiên bản phần mềm không thuộc định danh.** Nâng từ bản lỗi này lên bản vẫn lỗi thì lỗi
  *chưa* được vá; nếu version nằm trong băm, lần nâng cấp đó sẽ bị ghi thành "đã vá + lỗi
  mới" và che mất fix giả.
- **"Không thấy" chưa phải "đã vá".** Lỗi chỉ được chuyển sang *fixed* khi lần quét đó **có
  kiểm tra lại đúng chỗ đó** mà không thấy: máy trả lời, cổng nằm trong danh sách đã quét,
  scanner tương ứng có chạy. Máy tắt, firewall chặn, scanner bị bỏ qua → trạng thái giữ
  nguyên. Đây là lý do F7 phải lưu `status` của run và danh sách scanner đã chạy.
- **Định danh của máy khó hơn định danh của lỗi.** IP đổi (DHCP, cloud), một tên trỏ nhiều
  máy, một máy nhiều tên. Công cụ thật ưu tiên định danh bền: agent UUID → MAC → tên máy
  (NetBIOS / FQDN) → IP. Quét từ xa không agent thì IP là thứ tốt nhất có được.
- Thay đổi công thức băm là chuyện lớn: mọi lịch sử cũ mất liên kết. Vì vậy công thức phải có
  **số phiên bản**, và khi đổi thì tính lại băm cho dữ liệu cũ (nếu còn đủ dữ liệu) hoặc
  chấp nhận một điểm đứt và ghi rõ.
- Kết quả so hai lần quét (**diff**) mới là thứ người dùng đọc, không phải danh sách đầy đủ:
  "đêm qua có 3 lỗi mới, 5 lỗi đã vá, 1 fix giả".

**ReconKit có theo không**

| Thực tế yêu cầu | ReconKit hiện tại |
|---|---|
| Định danh = ở đâu + lỗi gì, không gồm câu chữ | ✅ F8: IP + port + protocol + CVE / `rule_id` |
| Version không nằm trong định danh | ✅ F8 |
| Công thức băm có số phiên bản | ✅ F8: `v2:<sha256>`; băm cũ giữ nguyên, không so với băm mới |
| Một lỗi do nhiều tool báo → một finding | ✅ F8: orchestrator gộp theo fingerprint |
| Finding nối được về đúng cổng, đúng máy | ✅ F7: `finding.service_id` |
| Biết lần quét có thật sự kiểm tra hay không | ✅ `feat/diff`: host trả lời + cổng chắc chắn được quét + cùng loại dữ liệu CVE; host im lặng → `not_responding` |
| Trạng thái, first seen / last seen, diff | ✅ `feat/diff` (kho tài sản + `finding_event`, `reconkit diff`) |
| Định danh máy bền hơn IP | ❌ chỉ có IP → D1 |
| Risk accepted / false positive có lý do và hạn | ⚠️ risk accepted (lý do + hạn, hết hạn tự mở lại) ✅; false positive: dùng accepted kèm lý do |
| SLA, MTTR | ❌ → sau khi có first seen / last seen |

Kết luận: fingerprint là **nền** của vòng đời, nhưng tự nó chưa phải vòng đời. Sau F8,
ReconKit trả lời được "hai finding này có phải một lỗi không"; còn "lỗi này đang ở trạng thái
nào, mở bao lâu rồi" cần kho tài sản và lịch sử của D1. Sơ đồ trạng thái đã chốt nằm trong
[`THIET-KE.md`](THIET-KE.md), mục "Vòng đời một lỗ hổng".

---

## Bài 5 — Kiến trúc: pipeline, plugin, repository, transaction, migration

**Thuật ngữ**

- **Pipeline / stage**: một việc lớn chia thành các bước nối tiếp, mỗi bước nhận đầu ra của
  bước trước. Lợi ích: mỗi bước kiểm thử được riêng, thêm bước mới không phải sửa bước cũ.
- **Plugin / adapter** (còn gọi *ports & adapters*, *hexagonal architecture*): lõi định nghĩa
  một **hợp đồng** (port); mỗi công cụ ngoài được bọc bởi một adapter thực hiện hợp đồng đó.
  Lõi không biết nmap hay nuclei là gì, chỉ biết "một thứ có `scan(target)`".
- **Structural typing / Protocol** (Python `typing.Protocol`): một class "là" plugin nếu nó có
  đúng các method, không cần kế thừa. Hợp đồng nằm ở kiểu, mypy kiểm tra.
- **Repository**: một lớp giấu SQL sau các method nghiệp vụ (`save_run`, `load_run`…). Phần
  còn lại của chương trình không viết SQL, nên đổi cơ sở dữ liệu là việc của một lớp.
- **Transaction / unit of work**: một nhóm thay đổi được ghi **tất cả hoặc không gì cả**
  (ACID: Atomicity, Consistency, Isolation, Durability). Máy sập giữa chừng thì DB vẫn nhất
  quán.
- **Schema migration**: mỗi thay đổi cấu trúc DB là một bước có số thứ tự, áp dụng một lần,
  theo thứ tự, ghi lại đã áp dụng tới đâu. **Forward-only**: không sửa migration đã phát hành.
- **Dependency injection**: thứ gì phụ thuộc thế giới bên ngoài (DNS, đồng hồ, mạng, tiến
  trình con) được *truyền vào* thay vì gọi thẳng, để test thay bằng bản giả.
- **Lõi thuần (pure core), vỏ I/O (imperative shell)**: logic quyết định viết thành hàm thuần
  (không đọc mạng, không đọc đĩa); phần I/O mỏng bọc bên ngoài.
- **Append-only log + hash chain**: nhật ký chỉ được thêm, mỗi bản ghi băm cả bản ghi trước
  (như git, Certificate Transparency): sửa quá khứ là lộ.

**Thực tế người ta làm thế nào**

- Scanner lớn đều là **lõi + plugin**: OpenVAS/Greenbone có `gvmd` (quản lý) nói chuyện với các
  scanner qua giao thức OSP, và hàng chục nghìn *NVT* (plugin kiểm tra) viết riêng; Nessus có
  hơn 200.000 plugin; nuclei = engine + template YAML. Không ai sửa lõi để thêm một kiểm tra.
- Hợp đồng plugin là thứ **khó đổi nhất**: đổi nó là sửa mọi plugin. Vì thế người ta đóng băng
  nó sớm và thêm trường *tuỳ chọn* thay vì đổi nghĩa trường cũ (ReconKit: `ScanResult` thêm
  `notes`, `cleared` mà không plugin cũ nào phải sửa).
- Migration: Alembic (SQLAlchemy), Django migrations, Flyway, Liquibase — đều có **bảng phiên
  bản** trong DB, chạy tự động khi khởi động, và **sao lưu** trước khi chạy ở production.
  Migration "down" hiếm khi dùng thật; thay vào đó là *expand → migrate → contract* (thêm cột
  mới, chuyển dữ liệu, rồi mới bỏ cột cũ) để không phải dừng dịch vụ.
- Mỗi "đơn vị nghiệp vụ" là một transaction: một lần quét được lưu trọn vẹn hoặc không lưu.
  Những thứ phải luôn khớp nhau (run, kho tài sản, nhật ký audit) nằm **cùng một transaction**.
- Hệ thống thật tách **trạng thái hiện tại** (kho tài sản) và **lịch sử** (các run, các sự kiện).
  Một số đi xa hơn với *event sourcing*: chỉ lưu sự kiện, trạng thái là kết quả phát lại sự
  kiện — ReconKit dùng đúng ý này cho `rebuild_inventory`.
- Test được nhờ injection: CI không có nmap, không có mạng, không có DNS thật; mọi thứ đó phải
  thay được bằng bản giả.

**ReconKit có theo không**

| Thực tế | ReconKit |
|---|---|
| Lõi + plugin, lõi không biết tool | ✅ `ScannerPlugin`, `DiscoveryPlugin`, `CheckPlugin`, `CveSource` là `Protocol`; orchestrator chỉ biết thứ tự các bước |
| Pipeline nhiều bước, mỗi bước test riêng | ✅ scope → (discovery) → scanner → check → CVE → rút lại đoán sai → fingerprint → lưu (run + kho + audit) |
| Hợp đồng plugin mở rộng mà không phá | ✅ chỉ thêm trường có giá trị mặc định (`notes`, `cleared`, `no_response`) |
| Repository giấu SQL | ✅ `Storage`, `CveCache`; `inventory_store` cho phần kho |
| Một run = một transaction (kể cả kho + audit) | ✅ `save_run` (`BEGIN IMMEDIATE`), lỗi giữa chừng → rollback |
| Migration có phiên bản, chạy tự động, sao lưu trước | ✅ v1 → v12, `schema_version`, `<db>.v<N>.bak`, `foreign_key_check` trước commit, từ chối DB mới hơn |
| Trạng thái hiện tại tách lịch sử, phát lại được | ✅ kho tài sản + run + `finding_event`; `inventory --rebuild` |
| Lõi thuần, I/O tiêm vào | ✅ `inventory.py`, `diff.py`, `version.py`, `debian.py`, `graph.py` là hàm thuần; resolver, clock, fetch, sleep, subprocess đều thay được |
| Nhật ký chống sửa | ✅ chuỗi băm audit (G21) |
| Nạp plugin động (entry points) | ❌ danh sách plugin viết trong CLI; thêm tool là sửa CLI một dòng |
| Chạy plugin song song | ❌ tuần tự; một lần quét = một tiến trình |
| Nhiều tiến trình ghi đồng thời, quy mô lớn | ⚠️ SQLite + khoá ghi; đủ cho vài worker, không cho hàng trăm (→ PostgreSQL) |
| ORM | ❌ SQL viết tay, có chủ đích: lõi không phụ thuộc thư viện ngoài |

Kết luận: kiến trúc theo đúng các mẫu chuẩn, và các chỗ chưa theo (nạp plugin động, song
song, PostgreSQL) đều là bài toán **quy mô**, không phải bài toán **đúng/sai** — thứ tự ưu tiên
đúng cho một công cụ mà dữ liệu sai còn nguy hiểm hơn chậm.

---

## Bài 6 — Công cụ thật so với ReconKit

**Thuật ngữ**

- **Vulnerability scanner** (OpenVAS/Greenbone, Nessus, Qualys VMDR, Rapid7 InsightVM): quét
  mạng + kiểm tra lỗ hổng bằng thư viện plugin riêng, có quét có đăng nhập, quản lý tài sản,
  báo cáo, lập lịch.
- **Template scanner** (nuclei): engine nhỏ + template cộng đồng; mạnh ở web và lỗi mới.
- **Vulnerability management / ASPM** (DefectDojo, Faraday): không tự quét; **gom** kết quả của
  nhiều scanner, khử trùng lặp, theo dõi vòng đời, SLA, ticket.
- **Attack surface management (ASM/EASM)**: liên tục tìm tài sản lộ ra Internet (subdomain,
  chứng chỉ, IP) — Censys, Shodan, ProjectDiscovery Cloud.
- **Authenticated scan / agent**: đăng nhập (SSH/WinRM) hoặc cài agent để đọc gói đã cài — kết
  quả chính xác hơn đoán theo banner.
- **Risk-based prioritization**: xếp theo khả năng bị khai thác (KEV, EPSS, VPR của Tenable,
  TruRisk của Qualys) chứ không chỉ CVSS.

**Thực tế người ta làm thế nào**

- Doanh nghiệp thường **kết hợp**: một scanner hạ tầng (Nessus/OpenVAS) + nuclei cho web + một
  nền tảng quản lý (DefectDojo) làm "nguồn sự thật" về lỗi, nối với Jira để giao việc.
- Phát hiện lỗi chủ yếu vẫn là **so phiên bản** (banner hoặc gói đã cài); kiểm tra chủ động
  (gửi payload) chỉ cho một phần nhỏ, vì rủi ro làm hỏng dịch vụ. Quét có đăng nhập được
  khuyến nghị cho mạng nội bộ vì loại bỏ phần lớn báo sai do backport.
- Xếp ưu tiên: CISA khuyến nghị xử lý **KEV trước**; EPSS dùng để lọc phần còn lại.
- Pháp lý / RoE: công cụ thương mại có **scan window**, giới hạn băng thông, danh sách loại trừ,
  nhật ký ai chạy gì — vì quét nhầm là sự cố thật.

**ReconKit có theo không**

| Khả năng | OpenVAS / Nessus | nuclei | DefectDojo | ReconKit |
|---|---|---|---|---|
| Quét cổng / dịch vụ | ✅ riêng | — | — | ✅ qua nmap (IPv4 + IPv6) |
| Tìm subdomain | ⚠️ ít | — | — | ✅ qua subfinder, mỗi tên kiểm scope |
| Thư viện kiểm tra lỗi riêng | ✅ hàng chục / trăm nghìn plugin | ✅ template | — | ❌ không có; dùng NVD (theo version) + nuclei (chủ động) |
| Quét có đăng nhập | ✅ Linux, Windows, mạng | — | — | ⚠️ chỉ Debian qua SSH key |
| Kho tài sản, vòng đời lỗi, fix giả | ✅ | — | ✅ (mạnh nhất) | ✅ D1: mới / mở / báo sửa / xác minh vá / fix giả / tái xuất hiện / chấp nhận rủi ro |
| Xếp ưu tiên theo khai thác | ✅ (VPR…) | ⚠️ EPSS trong template | ⚠️ | ✅ KEV → EPSS → CVSS |
| Bằng chứng gốc giữ lại, có băm | ⚠️ | ⚠️ | ⚠️ | ✅ output gốc nén + SHA-256, nằm trong chuỗi audit |
| Cổng scope trước mọi gói tin, kiểm lại kết quả | ⚠️ danh sách target | ❌ | — | ✅ phân giải một lần, mọi IP phải trong scope, `@expires`, `@window` |
| Nhật ký audit chống sửa | ⚠️ log | ❌ | ⚠️ | ✅ chuỗi băm, `audit --verify` |
| Báo cáo | ✅ PDF/HTML/CSV | JSON | ✅ | ✅ HTML (bản đồ offline), JSON, SARIF |
| Lập lịch, nhiều scanner phân tán | ✅ | — | — | ✅ Redis + RQ, nhiều worker, scheduler có khoá |
| Giao diện web, phân quyền | ✅ | ❌ | ✅ | ⚠️ dashboard + API, 2 vai trò (chưa theo target) |

Kết luận: ReconKit **không** thay được Nessus hay OpenVAS — nó không có thư viện kiểm tra
riêng, và cũng không nên tự viết. Vị trí đúng của nó là một **bộ điều phối** bọc các công cụ
mở (nmap, subfinder, nuclei, NVD), mạnh ở những chỗ các công cụ đó yếu: **đúng phạm vi** (scope
gate, giấy phép, khung giờ), **dữ liệu đúng qua thời gian** (fingerprint, vòng đời, chỉ kết
luận "đã vá" khi thật sự kiểm tra lại), **bằng chứng và trách nhiệm** (output gốc có băm, chuỗi
audit). Muốn dùng trong doanh nghiệp, bước tự nhiên là xuất SARIF sang DefectDojo và để
ReconKit lo phần quét định kỳ có kiểm soát.

---

## Bài 7 — Từ công cụ thành dịch vụ: hàng đợi, web an toàn, container, lab cô lập

**Thuật ngữ**

- **Job queue / worker** (Redis + RQ, Celery, Sidekiq): ai cần quét thì *xếp hàng* một job,
  các worker lấy ra chạy. Tách người yêu cầu khỏi việc nặng, chạy song song, sống sót qua
  restart. **Scheduler** chỉ là thứ xếp hàng theo giờ.
- **Idempotency / at-most-once**: cùng một việc không được chạy hai lần vì hai scheduler, hai
  lần bấm nút → khoá (Redis `SET NX EX`), khoá theo vòng, ghi "lần xếp hàng cuối".
- **Bearer token, session cookie, CSRF**: script gửi token trong header; trình duyệt giữ phiên
  trong cookie **HttpOnly** (JS không đọc được → XSS không lấy được) và **SameSite**. Cookie tự
  đi theo request từ trang khác → cần chống **CSRF** (header tự đặt mà trang khác không gửi được
  nếu không có CORS).
- **CSP** (Content-Security-Policy): trình duyệt chỉ chạy script / gọi mạng tới nơi được liệt kê
  → dữ liệu độc (banner chứa `<script>`) không chạy được dù lỡ lọt vào trang.
- **Least privilege trong container**: không chạy root, `cap_drop: ALL`, chỉ trả lại
  capability cần (`NET_RAW` cho raw socket), `no-new-privileges`, root FS chỉ đọc. **File
  capability** (`setcap`) cho một binary quyền cụ thể mà không cần root.
- **Supply chain**: ghim image theo **digest**, gói theo **phiên bản + mã băm** (`--require-hashes`)
  → bản build sau không lặng lẽ kéo về thứ khác.
- **Fail closed**: cấu hình hỏng thì *từ chối*, không chạy tiếp bằng cấu hình cũ (token đã thu
  hồi vẫn còn hiệu lực là lỗ hổng).

**Thực tế người ta làm thế nào**

- Dịch vụ quét thật (Nessus Manager, Greenbone) đều tách **giao diện / API** khỏi **scanner**
  (worker, có khi đặt ở mạng khác), trao đổi qua hàng đợi; scanner là thành phần nhiều quyền
  nhất nên bị khoá chặt nhất.
- Người dùng chỉ được chọn **tài sản đã đăng ký**, không gõ địa chỉ tuỳ ý — nếu không, dịch vụ
  thành "máy quét hộ" (SSRF / lạm dụng).
- Web nội bộ: TLS ở reverse proxy, phiên phía server có hết hạn, rate limit đăng nhập, SSO
  (OIDC) thay cho token tĩnh, phân quyền theo nhóm tài sản.
- Container: image tối giản, không root, ký image (cosign), SBOM, quét image (Trivy) trong CI,
  bot cập nhật digest (Renovate / Dependabot).
- Backup: dùng cơ chế backup của database (không chép file đang ghi), **kiểm tra bản sao**, đẩy
  ra kho ngoài có mã hoá, và **diễn tập khôi phục**.
- Lab thực hành (HackTheBox, vulhub): mục tiêu có lỗ hổng luôn ở mạng **không ra Internet**.

**ReconKit có theo không**

| Điểm | ReconKit |
|---|---|
| Tách web / scheduler / worker qua hàng đợi | ✅ Redis + RQ; worker chạy đúng đường quét của CLI (`scanning.execute`) |
| Chỉ quét tài sản đã khai | ✅ job chỉ mang *tên* target; worker đọc lại `service.toml`; request có trường lạ → 422 |
| Không xếp trùng | ✅ khoá mỗi vòng scheduler; "đến hạn" tính theo target **và** profile |
| Token chỉ lưu băm, so sánh thời gian hằng | ✅ SHA-256 + `hmac.compare_digest` |
| Cookie HttpOnly + SameSite + chống CSRF | ✅ header `X-ReconKit` bắt buộc khi đi bằng cookie |
| CSP chặt, chỉ ghi dữ liệu dạng chữ | ✅ dashboard `script-src 'self'`; báo cáo chỉ script có băm |
| Fail closed khi cấu hình hỏng | ✅ API từ chối mọi request tới khi sửa |
| Container không root, ít capability | ✅ uid 10001, `cap_drop: ALL`, chỉ worker có `NET_RAW`, FS chỉ đọc |
| Ghim digest + mã băm | ✅ `docker/*.lock`, `--require-hashes` |
| Backup có kiểm tra | ✅ `reconkit backup` (online, integrity, audit, SHA-256, `--verify`) |
| Rate limit, phiên phía server, SSO, phân quyền theo target | ❌ G23 |
| Ký image, SBOM, quét image | ❌ G20 |

**Bài học từ lúc làm** (đều đã kiểm bằng chạy thật, không chỉ đọc tài liệu):

- `internal: true` của Docker **chặn mọi gói có đích ngoài subnet** → không dựng được router
  giữa hai mạng internal; còn host lại vẫn chạm được qua địa chỉ gateway. Cách đúng cho lab:
  bridge không có địa chỉ phía host (`inhibit_ipv4`) + tắt NAT.
- File capability **không có tác dụng** khi `no-new-privileges` bật, và làm `exec` **thất bại**
  (EPERM) nếu capability không nằm trong bounding set của container → chỉ cấp `cap_net_raw`
  (Docker cho sẵn), không thêm `NET_ADMIN` thừa.
- Server Redis "giả" qua TCP (fakeredis) không đủ cho redis-py 8 (`CLIENT INFO`): test đơn vị
  dùng fakeredis trong process, còn kiểm tra đầu-cuối phải dùng Redis thật.
- Trên Windows không có `fork()` / `SIGALRM`: worker chạy job trong tiến trình, hẹn giờ bằng
  luồng — ổn để phát triển, còn chạy thật thì worker nên ở Linux (container).

---

## Bài 8 — nuclei & subfinder ngoài đời thật

**Thuật ngữ**

- **Template (nuclei)**: file YAML mô tả request gửi đi và điều kiện (matcher) để coi là
  "trúng". Có nhiều *giao thức*: `http` (~11.800 template), `javascript` / `tcp` (dịch vụ mạng:
  SSH, Redis, SMB…), `ssl`, `dns`, `headless` (trình duyệt), `code` (chạy script trên **máy
  quét**), `file` (đọc file trên máy quét). Loại cuối cùng nguy hiểm cho chính máy quét.
- **Template signing**: ProjectDiscovery ký template chính thức (`# digest:` cuối file);
  `-dut` chỉ chạy template có chữ ký hợp lệ → template bị sửa hay bị cài cắm không chạy.
- **OAST / interactsh**: kiểm tra "mù" — gửi payload khiến mục tiêu gọi ra một máy chủ ngoài
  (DNS/HTTP callback) để chứng minh lỗi (Log4Shell, SSRF mù). Mặc định dùng máy chủ công cộng
  của ProjectDiscovery → dữ liệu engagement đi ra ngoài.
- **Passive vs active recon**: subfinder hỏi *nguồn công khai* (certificate transparency, bộ dữ
  liệu DNS, công cụ tìm kiếm), không gửi gì tới mục tiêu. Brute-force DNS / quét là chủ động.
- **Wildcard DNS**: bản ghi `*.example.com` trả lời **mọi** tên → mọi tên "rác" đều phân giải
  được. Cách phát hiện chuẩn: hỏi một tên ngẫu nhiên; trả lời được thì zone là wildcard.

**Thực tế người ta làm thế nào**

- Đội pentest / bug bounty chạy nuclei theo **tầng**: nhận diện công nghệ trước, rồi chỉ chạy
  template hợp với công nghệ đó (`-as`, hoặc chọn theo tag), mức `info` để làm bản đồ chứ không
  làm "lỗ hổng". Doanh nghiệp tự dựng **interactsh** nội bộ.
- Templates là phần cập nhật nhanh nhất (hằng ngày); bản build cố định ghim phiên bản và cập
  nhật có kiểm soát, giống mọi phụ thuộc khác; template tự viết được ký bằng khoá riêng.
- Kết quả subfinder luôn được **lọc** trước khi dùng: phân giải (dnsx/massdns, song song), bỏ
  wildcard, giới hạn số lượng, rồi mới tới httpx/nmap.

**ReconKit có theo không** — và những gì chỉ lộ ra khi chạy thật:

| Hiện tượng đo được (lab, nuclei 3.11.1, templates 10.5.2, subfinder 2.17.0) | Đã xử lý |
|---|---|
| Profile `standard` (900 s) + vài web server: nuclei vượt giờ → **cả lần quét thất bại**, mất kết quả nmap | ✅ một giới hạn chung, hết giờ giữ kết quả, run `partial` |
| Cổng SSH cho chạy qua mọi template: 147 s; chỉ template mạng (`-pt javascript,tcp,ssl`): tức thì, cùng kết quả. `-pt network` **không** phải tên hợp lệ (khớp 1 template) | ✅ lượt riêng cho dịch vụ không phải web, tên đã kiểm bằng `-tl` |
| CVE-2021-41773: phiên bản dính lỗi nhưng template **không** khai thác được với cấu hình mặc định của httpd | ✅ đúng là "firm", không phải "confirmed" (lab sau sẽ cấu hình khai thác được) |
| Finding nuclei thắng finding theo phiên bản nhưng làm rơi ngày KEV → Apache tụt từ P1 xuống P2 | ✅ gộp, lấy dữ liệu CVE từ cơ sở dữ liệu |
| nuclei ghi cấu hình vào `$HOME`, cần `.nuclei-ignore` cạnh cấu hình; chạy được với FS chỉ đọc khi có `NUCLEI_CONFIG_DIR` | ✅ thư mục cấu hình tạm mỗi lần chạy |
| subfinder trên `example.com`: 25.514 tên trong 3 s, 87% từ một nguồn rác | ✅ giới hạn, song song, lọc wildcard, ghi chú gộp |
| interactsh, che dữ liệu trong bằng chứng | ❌ G24 |

Bài học chung: một plugin "đã có test" bằng output mẫu vẫn chưa phải plugin chạy được. Output
mẫu cho biết **định dạng**; chỉ chạy thật mới cho biết **thời gian, khối lượng, và hành vi lúc
hỏng** — ba thứ quyết định nó có dùng được trong vận hành hay không.

---

## Bài 9 — Cho AI dùng công cụ bảo mật: MCP, xác nhận của con người, prompt injection

**Thuật ngữ**

- **MCP (Model Context Protocol)**: chuẩn để một ứng dụng AI (client) gọi *tool* của một
  *server*. Server khai tool (tên, mô tả, schema tham số); model chọn tool và điền tham số.
- **Elicitation**: server xin client hỏi *người dùng* một câu có cấu trúc (vd "xác nhận?").
  Bản giao thức 2026-07-28 làm việc này bằng vòng "input required" (client trả lời rồi gọi lại).
- **Human-in-the-loop**: hành động có hậu quả cần một người đồng ý — không phải model.
- **Prompt injection gián tiếp**: chỉ dẫn độc nằm trong *dữ liệu* model đọc (trang web, email,
  banner của dịch vụ bị quét), không phải trong lời người dùng.
- **Confused deputy**: chương trình có quyền bị kẻ khác lợi dụng để làm việc mà kẻ đó không có
  quyền — ở đây: AI có token quét bị dữ liệu độc "nhờ" quét chỗ khác.

**Thực tế người ta làm thế nào**

- Tool cho AI được cấp quyền **tối thiểu**, tách đọc / ghi; hành động ghi cần xác nhận hoặc qua
  quy trình phê duyệt; mọi thứ ghi log dưới danh tính riêng của agent.
- Không để model tự chọn *đích* của hành động nguy hiểm: chọn trong danh sách đã duyệt.
- Dữ liệu từ bên ngoài luôn được đánh dấu là dữ liệu; hệ thống quan trọng không dựa vào việc
  model "ngoan" để an toàn.

**ReconKit có theo không**

| Điểm | ReconKit |
|---|---|
| Một mô hình quyền cho người và AI | ✅ MCP là client của web API: token, vai trò, audit như nhau |
| Model không chọn được địa chỉ quét | ✅ chỉ tên target trong `service.toml`; `8.8.8.8` → từ chối |
| Người xác nhận hành động | ✅ elicitation; câu trả lời không phải tham số tool → model không tự điền |
| Quyết định có trách nhiệm để lại cho người | ✅ không có tool chấp nhận rủi ro |
| Dữ liệu quét là dữ liệu | ✅ bỏ ký tự điều khiển / đảo chiều, cắt ngắn, mô tả tool nói rõ |
| Client tự trả lời "đồng ý" | ❌ không chặn được ở server — G26 |

**Bài học khi làm** (đã kiểm bằng chạy thật):

- SDK MCP Python đã sang **v2** (`FastMCP` → `MCPServer`, thuộc tính snake_case); `ctx.elicit()`
  *không* chạy với giao thức mới — phải dùng `Annotated[..., Resolve(fn)]` trả về `Elicit(...)`.
  Đọc mã nguồn của bản đã cài thay vì tin trí nhớ.
- Lỗi thường trong tool bị giấu thành "Error executing tool"; muốn model đọc được lý do thì
  raise `ToolError`.
- Tool trả về danh sách thì mỗi phần tử là một khối text riêng — client nên đọc bản có cấu trúc.
