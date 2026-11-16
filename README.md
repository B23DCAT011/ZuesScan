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
```

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

> File DB chứa toàn bộ kết quả và output gốc của các lần quét: coi nó là dữ liệu nhạy cảm của
> đợt kiểm thử, không chia sẻ và không commit.

| Exit code | Ý nghĩa |
|---|---|
| 0 | Quét xong, kết quả đã lưu vào DB |
| 1 | Không dùng được database (hỏng, không phải SQLite, hoặc schema mới hơn bản ReconKit này) — chưa quét gì |
| 2 | Đầu vào sai: không thấy file scope, hoặc file scope có dòng không hợp lệ |
| 3 | Từ chối: target nằm ngoài scope, tên miền trỏ tới IP ngoài scope, hoặc target bị denylist phủ kín |
| 4 | Quét thất bại, lưu thành run `failed` **không có kết quả**: thiếu nmap, nmap lỗi / quá thời gian, không phân giải được tên, không host nào trả lời |
