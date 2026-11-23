# Viết plugin cho ReconKit

ReconKit là bộ điều phối: nó không tự quét, mà gọi **plugin** — mỗi plugin bọc một công cụ
(nmap, nuclei, subfinder…) hoặc một bài kiểm viết bằng Python. Thêm công cụ mới **không cần sửa
ReconKit**: viết plugin thành một gói Python riêng, cài vào cùng môi trường, và ReconKit tự thấy.

```bash
pip install reconkit-exposed-git          # hoặc: pip install ./examples/reconkit-exposed-git
reconkit plugins                          # exposed-git  check  active  yes  reconkit-exposed-git ...
reconkit scan 10.0.0.0/24 --scope scope.txt --check exposed-git
```

Bớt công cụ: gỡ gói (`pip uninstall`), hoặc đơn giản là không chọn nó. Plugin dựng sẵn không gỡ
được nhưng chỉ chạy khi được chọn (nmap là scanner mặc định).

## Ba loại plugin

| Loại | Làm gì | Hợp đồng (`reconkit.plugins.base`) | Dựng sẵn |
|---|---|---|---|
| `scanner` | tìm host và dịch vụ trên các địa chỉ đã duyệt | `scan(target) -> ScanResult` | nmap |
| `check` | kiểm tra những gì scanner tìm được | `check(plan, assets) -> ScanResult` | nuclei, ssh-packages |
| `discovery` | tìm *tên* để quét (chưa quét gì) | `discover(domain) -> DiscoveryResult` | subfinder |

Mọi plugin có thêm `name`, `is_available()` (công cụ có trên máy không), `version()` (ghi vào
mỗi run; không bao giờ raise) và thuộc tính lớp **`activity`**.

## Mức chủ động và `@activity`

| `activity` | Nghĩa | Ví dụ |
|---|---|---|
| `passive` | chỉ hỏi bên thứ ba, không gì tới mục tiêu | subfinder |
| `scan` | tìm cái đang có: quét cổng, nhận diện dịch vụ, đăng nhập chỉ đọc | nmap, ssh-packages |
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

## Đóng gói

```toml
# pyproject.toml
[project]
name = "reconkit-exposed-git"

[project.entry-points."reconkit.plugins"]
exposed-git = "reconkit_exposed_git:PLUGIN"
```

```python
from reconkit.plugins.registry import PluginContext, PluginSpec
from reconkit.scope import Activity

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
trong `reconkit plugins` / `reconkit doctor` — không bao giờ làm hỏng các plugin khác.

Ví dụ đầy đủ, chạy được: [`examples/reconkit-exposed-git`](../examples/reconkit-exposed-git).

## Kiểm tra hợp đồng trong test của plugin

```python
from reconkit.plugins import contract


def test_keeps_the_contract():
    contract.assert_ok(contract.check_spec(PLUGIN))
    contract.assert_ok(contract.check_check(ExposedGitCheck(), plan, assets))
```

`check_scanner`, `check_check`, `check_discovery` trả về danh sách quy tắc bị vi phạm (báo cùng
lúc): có tên và `activity`, `version()` không raise, không báo host ngoài phạm vi được giao, giữ
output gốc, lỗi là `ScanError`, tên tìm được nằm dưới đúng tên miền.

## Chọn plugin khi quét

| | Dòng lệnh | `service.toml` (mỗi target) |
|---|---|---|
| Scanner | `--scanner NAME` (lặp lại được; mặc định `nmap`) | `scanners = ["nmap"]` |
| Check | `--check NAME`; `--nuclei` = `--check nuclei` | `checks = ["nuclei", "exposed-git"]` |
| Discovery | `--discoverer NAME`; `--discover` = subfinder | `discoverers = ["subfinder"]` |

## Giới hạn

Plugin chạy **trong cùng tiến trình** với ReconKit và có mọi quyền của nó; `activity` là lời khai
của plugin. Chỉ cài plugin từ nguồn tin cậy — xem G25 trong [`KNOWN-GAPS.md`](KNOWN-GAPS.md).
