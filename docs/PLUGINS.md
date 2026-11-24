# Viết plugin cho ZuesScan

ZuesScan là bộ điều phối: nó không tự quét, mà gọi **plugin** — mỗi plugin bọc một công cụ
(nmap, nuclei, subfinder…) hoặc một bài kiểm viết bằng Python. Thêm công cụ mới **không cần sửa
ZuesScan**: viết plugin thành một gói Python riêng, cài vào cùng môi trường, và ZuesScan tự thấy.

```bash
pip install zues-exposed-git          # hoặc: pip install ./examples/zues-exposed-git
zues plugins                          # exposed-git  check  active  yes  zues-exposed-git ...
zues scan 10.0.0.0/24 --scope scope.txt --check exposed-git
```

Bớt công cụ: gỡ gói (`pip uninstall`), hoặc đơn giản là không chọn nó. Plugin dựng sẵn không gỡ
được nhưng chỉ chạy khi được chọn (nmap là scanner mặc định).

## Ba loại plugin

| Loại | Làm gì | Hợp đồng (`zues_scan.plugins.base`) | Dựng sẵn |
|---|---|---|---|
| `scanner` | tìm host và dịch vụ trên các địa chỉ đã duyệt | `scan(target) -> ScanResult` | nmap, naabu |
| `check` | kiểm tra những gì scanner tìm được | `check(plan, assets) -> ScanResult` | httpx, nuclei, ssh-packages |
| `discovery` | tìm *tên* để quét (chưa quét gì) | `discover(domain) -> DiscoveryResult` | subfinder, dnsx |

Mọi plugin có thêm `name`, `is_available()` (công cụ có trên máy không), `version()` (ghi vào
mỗi run; không bao giờ raise) và thuộc tính lớp **`activity`**.

## Mức chủ động và `@activity`

| `activity` | Nghĩa | Ví dụ |
|---|---|---|
| `passive` | chỉ hỏi bên thứ ba, không gì tới mục tiêu | subfinder |
| `scan` | tìm cái đang có: quét cổng, nhận diện dịch vụ, đăng nhập chỉ đọc, hỏi DNS của mục tiêu | nmap, naabu, httpx, ssh-packages, dnsx |
| `active` | thử lỗi: request được chế tạo, kiểm tra khai thác | nuclei, exposed-git |

File scope đặt **mức trần** bằng `@activity` (mặc định `scan`). Plugin vượt trần bị từ chối
*trước khi gửi gói tin nào*, và lần từ chối được ghi vào audit trail. Lý do: Rules of Engagement
ngoài thực tế ghi rõ có được khai thác hay không; điều đó phải nằm trong giấy phép, không phải
trong một cờ dòng lệnh.

Plugin không khai báo `activity` bị coi là đi xa nhất có thể theo loại của nó (check → `active`).
Plugin khai thấp hơn `PluginSpec` của chính nó thì registry từ chối dựng.

## Bốn quy tắc an toàn

1. **Chỉ chạm các địa chỉ đã được duyệt**: `target.addresses` (trừ `target.exclude`) với scanner,
   `asset.ip` của các host được giao với check. Không tự phân giải tên (tên có thể trỏ đi chỗ
   khác lúc chạy), không đi theo redirect sang địa chỉ khác.
2. **Giữ output gốc** của công cụ trong `ScanResult.raw` — đó là bằng chứng của run.
3. **Lỗi là `ScanError`** (kèm `plugin=`, stderr, output nếu có), không bao giờ trả kết quả rỗng
   để báo lỗi: rỗng nghĩa là "đã kiểm và không thấy gì".
4. **Dữ liệu từ mục tiêu là không tin cậy**: chỉ lưu và hiển thị dưới dạng chữ.

Orchestrator vẫn kiểm lại (host ngoài scope bị bỏ, check không được thêm host mới), nhưng plugin
đúng hợp đồng thì không phụ thuộc vào lớp phòng thủ đó.

Một check trả về finding trên các host được giao; ngoài ra nó có thể trả `Service(port, web=WebPage(...))`
(như httpx): thông tin web được gắn vào **dịch vụ mà lần quét đã tìm thấy** trên cùng cổng — một
cổng check tự nhận mà scanner không thấy thì bị bỏ qua. Công nghệ có phiên bản trong `WebPage`
được bước CVE đối chiếu (`zues_scan.cve.match.components`).

## Đóng gói

```toml
# pyproject.toml
[project]
name = "zues-exposed-git"

[project.entry-points."zues_scan.plugins"]
exposed-git = "zues_exposed_git:PLUGIN"
```

```python
from zues_scan.plugins.registry import PluginContext, PluginSpec
from zues_scan.scope import Activity

PLUGIN = PluginSpec(
    name="exposed-git",
    kind="check",
    activity=Activity.ACTIVE,
    summary=".git directories served over HTTP",
    factory=lambda ctx: ExposedGitCheck(),  # ctx: profile, nuclei_templates, ...
    binary=None,  # hoặc tên chương trình cần có (doctor kiểm)
)
```

Gói hỏng (lỗi import, không phải `PluginSpec`, trùng tên plugin dựng sẵn) bị bỏ qua và báo
trong `zues plugins` / `zues doctor` — không bao giờ làm hỏng các plugin khác.

Ví dụ đầy đủ, chạy được: [`examples/zues-exposed-git`](../examples/zues-exposed-git).

## Kiểm tra hợp đồng trong test của plugin

```python
from zues_scan.plugins import contract


def test_keeps_the_contract():
    contract.assert_ok(contract.check_spec(PLUGIN))
    contract.assert_ok(contract.check_check(ExposedGitCheck(), plan, assets))
```

`check_scanner`, `check_check`, `check_discovery` trả về danh sách quy tắc bị vi phạm (báo cùng
lúc): có tên và `activity`, `version()` không raise, không báo host ngoài phạm vi được giao, giữ
output gốc, lỗi là `ScanError`, tên tìm được nằm dưới đúng tên miền.

## Cho dịch vụ nạp plugin: ghim

Plugin chạy với mọi quyền của ZuesScan (đọc được database, token, khoá SSH), và code của nó
chạy ngay khi được import. Vì vậy **dịch vụ** (web, worker, scheduler) chỉ nạp plugin dựng
sẵn và những plugin bên thứ ba mà cấu hình của nó **ghim**:

```bash
pip install zues-exposed-git          # trong image / venv của dịch vụ
zues plugins --pin exposed-git        # in ra mục cấu hình — đọc code của gói trước đã
```

```toml
[[plugins]]
name = "exposed-git"                  # tên plugin (entry point)
package = "zues-exposed-git"          # gói cung cấp nó
version = "0.1.0"
sha256 = "c33c0a3d…"                  # các file gói đã cài (theo RECORD của nó)
activity = "active"                   # mức BẠN đánh giá sau khi đọc code
```

Hoặc trong môi trường (compose, không có service.toml):
`ZUES_PLUGINS=exposed-git:active:zues-exposed-git==0.1.0:<sha256>` (nhiều mục: cách nhau bởi dấu
phẩy).

Lúc khởi động mỗi lần quét, ZuesScan kiểm **từ file trên đĩa, trước khi import**: đúng gói,
đúng phiên bản, mã băm của mọi file trong RECORD khớp (bỏ qua `__pycache__`, script do bộ cài
sinh ra ngoài site-packages, và file của bộ cài như `INSTALLER`), entry point trỏ vào module
của chính gói đó. Sai một điều thì plugin không được nạp, code của nó không chạy, `zues doctor`
báo lỗi; target dùng nó dừng với lý do rõ ràng thay vì quét thiếu.

- **`activity` là của người vận hành.** Cổng scope (`@activity`) dùng mức ghi trong pin; plugin
  tự khai cao hơn mức đó thì bị từ chối (nó trung thực về việc nó làm nhiều hơn bạn nghĩ), khai
  thấp hơn thì vẫn bị coi theo mức bạn ghi. `--pin` mặc định ghi `active` — mức cao nhất.
- **Pin là của một bản cài.** Ghim cái thực sự chạy: chạy `--pin` trong image sẽ triển khai.
  Dựng lại wheel từ mã nguồn bằng công cụ khác có thể cho metadata khác, tức pin khác.
- Gói cài kiểu editable (`pip install -e`) hoặc không có RECORD thì không ghim được: code của nó
  nằm ngoài các file đã cài.
- Không ghim gì: chỉ plugin dựng sẵn. `zues plugins --config service.toml` cho thấy dịch vụ nạp
  gì và vì sao một plugin bị bỏ.
- Dòng lệnh của bạn (`zues scan`) vẫn nạp mọi plugin đã cài — cài là đã quyết định — trừ khi
  đặt `ZUES_PLUGINS` (`none`: chỉ plugin dựng sẵn).

## Chọn plugin khi quét

| | Dòng lệnh | `service.toml` (mỗi target) |
|---|---|---|
| Scanner | `--scanner NAME` (lặp lại được; mặc định `nmap`) | `scanners = ["nmap"]` |
| Check | `--check NAME`; `--nuclei` = `--check nuclei` | `checks = ["nuclei", "exposed-git"]` |
| Discovery | `--discoverer NAME`; `--discover` = subfinder | `discoverers = ["subfinder", "dnsx"]` |

## Giới hạn

Plugin được ghim vẫn chạy **trong cùng tiến trình** với ZuesScan và có mọi quyền của nó: pin
bảo đảm đó đúng là code bạn đã đọc, không bảo đảm code đó vô hại. Phụ thuộc của plugin (gói
khác nó import) không nằm trong pin — ghim chúng khi dựng image (`pip install --require-hashes`).
Xem G25 trong [`KNOWN-GAPS.md`](KNOWN-GAPS.md).
