# Mini Vault - Hướng dẫn chạy và kiểm thử từ đầu đến cuối

Tài liệu này sử dụng PowerShell và giả định project nằm tại `D:\temp`.

## 1. Cài đặt

Mở PowerShell tại thư mục project:

```powershell
cd D:\temp

python -m venv .venv
.venv\Scripts\Activate.ps1

python -m pip install -r requirements.txt
python -m pytest -q
```

Kết quả test mong đợi:

```text
8 passed
```

## 2. Khởi động interactive shell

```powershell
python main.py --data-dir data shell
```

Các lệnh bên dưới được nhập tại dấu nhắc:

```text
mini-vault>
```

## 3. Khởi tạo và mở khóa Vault

```text
init
```

Nhập Master Passphrase dài ít nhất 12 ký tự hai lần.

Kiểm tra trạng thái:

```text
status
```

Kết quả:

```text
initialized
vault status: locked
```

Mở khóa:

```text
unlock
```

Nhập đúng Master Passphrase, sau đó kiểm tra:

```text
status
```

Kết quả:

```text
initialized
vault status: unlocked
```

## 4. Đăng ký hai tài khoản

```text
register alice@example.com
register bob@example.com
```

Mỗi passphrase phải dài ít nhất 12 ký tự. Ví dụ:

```text
Alice: alice-password123
Bob:   bob-password12345
```

## 5. Đăng nhập Alice

```text
login alice@example.com
```

Copy session token được trả về. Trong các lệnh dưới đây, thay `<ALICE_TOKEN>` bằng token thực tế.

## 6. KV encrypted storage và versioning

### Ghi version 1

```text
write --token <ALICE_TOKEN> --path db --data '{"username":"admin","password":"secret-v1"}'
```

Kết quả chứa các trường:

```json
{
  "path": "secret/alice@example.com/db",
  "version": 1,
  "created_at": "...",
  "updated_at": "..."
}
```

### Ghi đè để tạo version 2

```text
write --token <ALICE_TOKEN> --path db --data '{"username":"admin","password":"secret-v2"}'
```

### Đọc bản mới nhất

```text
read --token <ALICE_TOKEN> --path db
```

### Liệt kê các version

```text
list-versions --token <ALICE_TOKEN> --path db
```

### Đọc từng version

```text
read --token <ALICE_TOKEN> --path db --version 1
read --token <ALICE_TOKEN> --path db --version 2
```

## 7. Kiểm tra dữ liệu trên đĩa đã được mã hóa

Mở PowerShell thứ hai và chạy:

```powershell
Get-Content D:\temp\data\kv_store.json
```

File chỉ được chứa nonce, ciphertext, authentication tag, metadata và version. Không được thấy các chuỗi plaintext:

```text
secret-v1
secret-v2
```

## 8. Kiểm tra ownership bằng tài khoản Bob

Trong Mini Vault shell:

```text
login bob@example.com
```

Copy token thành `<BOB_TOKEN>`.

Bob thử đọc secret của Alice:

```text
read --token <BOB_TOKEN> --path secret/alice@example.com/db
```

Kết quả mong đợi:

```text
PERMISSION_DENIED
```

Alice vẫn đọc được secret của mình:

```text
read --token <ALICE_TOKEN> --path db
```

## 9. Tạo Transit encryption key

```text
create-key --token <ALICE_TOKEN> --key-name app-key
list-keys --token <ALICE_TOKEN>
```

Kết quả chỉ chứa metadata, không chứa AES key plaintext:

```json
{
  "key_name": "app-key",
  "owner_email": "alice@example.com",
  "key_usage": "ENCRYPT_DECRYPT"
}
```

## 10. Transit encrypt/decrypt

Chuỗi base64 `aGVsbG8=` tương ứng với `hello`.

Mã hóa:

```text
encrypt --token <ALICE_TOKEN> --key-name app-key --plaintext-b64 aGVsbG8=
```

Copy ciphertext dạng:

```text
vault:app-key:<BASE64_PAYLOAD>
```

Thay `<CIPHERTEXT>` bằng toàn bộ ciphertext vừa nhận rồi giải mã:

```text
decrypt --token <ALICE_TOKEN> --ciphertext <CIPHERTEXT>
```

Kết quả:

```text
aGVsbG8=
```

Bob thử sử dụng key của Alice:

```text
encrypt --token <BOB_TOKEN> --key-name app-key --plaintext-b64 aGVsbG8=
```

Kết quả:

```text
PERMISSION_DENIED
```

## 11. Transit signing key

```text
create-signing-key --token <ALICE_TOKEN> --key-name app-sign --algorithm ED25519
```

Ký message `hello`:

```text
sign --token <ALICE_TOKEN> --key-name app-sign --message-b64 aGVsbG8= --message-type RAW
```

Kết quả:

```json
{
  "signature_b64": "<SIGNATURE>",
  "key_name": "app-sign",
  "signing_algorithm": "ED25519"
}
```

Copy giá trị `signature_b64` để sử dụng trong các bước tiếp theo.

## 12. Verify chữ ký hợp lệ

Thay `<SIGNATURE>` bằng chữ ký vừa nhận:

```text
verify --token <ALICE_TOKEN> --key-name app-sign --message-b64 aGVsbG8= --message-type RAW --signature-b64 <SIGNATURE>
```

Kết quả:

```json
{
  "key_name": "app-sign",
  "signature_valid": true,
  "signing_algorithm": "ED25519"
}
```

## 13. Verify message bị thay đổi

`aGVsbG8h` tương ứng với `hello!`, khác message ban đầu:

```text
verify --token <ALICE_TOKEN> --key-name app-sign --message-b64 aGVsbG8h --message-type RAW --signature-b64 <SIGNATURE>
```

Kết quả:

```json
{
  "key_name": "app-sign",
  "signature_valid": false,
  "signing_algorithm": "ED25519"
}
```

## 14. Bật MFA TOTP

```text
enable-mfa --token <ALICE_TOKEN>
```

Nhập passphrase của Alice. Kết quả trả về:

```json
{
  "mfa_enabled": true,
  "secret": "...",
  "otpauth_uri": "otpauth://totp/..."
}
```

Thêm tài khoản vào Google Authenticator hoặc Microsoft Authenticator bằng `secret` hoặc `otpauth_uri`.

Kiểm tra trạng thái MFA:

```text
mfa-status --token <ALICE_TOKEN>
```

Thử đăng nhập không có OTP:

```text
login alice@example.com
```

Kết quả:

```text
Valid MFA code required
```

Đăng nhập với mã sáu chữ số hiện tại:

```text
login alice@example.com --otp 123456
```

Thay `123456` bằng mã trong Authenticator. Copy token mới thành `<MFA_TOKEN>`.

## 15. Kiểm tra audit hash-chain

Những lần Bob truy cập secret và key của Alice đã tạo audit event.

```text
verify-audit --token <MFA_TOKEN>
```

Kết quả:

```json
{
  "valid": true,
  "event_count": 2,
  "invalid_index": null
}
```

Có thể kiểm tra file trực tiếp trong PowerShell khác:

```powershell
Get-Content D:\temp\data\audit_log.json
Get-Content D:\temp\data\audit_head.json
```

## 16. Revoke Transit key

```text
revoke-key --token <MFA_TOKEN> --key-name app-key
```

Thử giải mã ciphertext cũ:

```text
decrypt --token <MFA_TOKEN> --ciphertext <CIPHERTEXT>
```

Kết quả:

```text
NOT_FOUND
```

## 17. Xóa KV secret

Lưu ý: thao tác này xóa cả version hiện tại và toàn bộ lịch sử.

```text
delete --token <MFA_TOKEN> --path db
```

Thử đọc lại:

```text
read --token <MFA_TOKEN> --path db
```

Kết quả:

```text
NOT_FOUND
```

## 18. Khóa và thoát

```text
lock
status
```

Kết quả:

```text
vault status: locked
```

Thử gọi Transit trong trạng thái locked:

```text
list-keys --token <MFA_TOKEN>
```

Kết quả:

```text
VAULT_LOCKED
```

Thoát shell:

```text
exit
```

Khi thoát shell, DEK trong RAM được xóa và Vault tự động chuyển về trạng thái khóa.
