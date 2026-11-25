# My Auth Go

Backend **Authentication & User Management API** — Go + Gin + MariaDB.
Produk dari [PRD.md](PRD.md), siap produksi.

Satu binary statis: migrasi database, seeder admin, server HTTP, semua di dalamnya.

## Fitur

| Area | Isi |
|---|---|
| Auth | Register, login, logout, refresh token **rotation**, forgot/reset password |
| JWT | Access token 15m + refresh token 7 hari, tipe token tidak bisa ditukar |
| Sesi | Token disimpan sebagai SHA-256; logout & ganti password mencabut semua token |
| User | CRUD lengkap + pagination, search, filter role/status, sorting aman |
| RBAC | `guest` / `admin`; guest hanya bisa akses & ubah data dirinya |
| Keamanan | bcrypt cost 12, rate limit per IP, lockout 5 gagal login, security headers, audit log |
| Dokumentasi | Swagger (dev), anotasi lengkap di controller |

## Arsitektur

Struktur folder **persis konsep PRD**:

```
my-auth-go/
├── cmd/api/main.go            entry point
├── modules/
│   ├── users/                 controller, service, repository,
│   │                          validator, model, routes, helper, me
│   ├── auth/                  controller, service, repository,
│   │                          validator, model, routes
│   └── health/                controller, routes
├── config/                    database.go, migrate.go, seeder.go
├── middlewares/               auth, security (headers/CORS/rate limit), logger
├── utils/                     response, password, token
├── exceptions/                AppError + recovery + centralized handler
├── routes/                    api.go (dependency graph)
├── docs/                      Swagger
├── tests/                     unit test
└── deploy/                    systemd unit
```

Aliran request: `routes → middleware → controller → service → repository → MariaDB`.
Controller tidak menyentuh SQL; repository tidak mengenal HTTP.

---

## Endpoint

| Method | Endpoint | Akses | Fungsi |
|---|---|---|---|
| POST | `/api/v1/auth/register` | publik | Registrasi (status `inactive`, tunggu aktivasi admin) |
| POST | `/api/v1/auth/login` | publik | Login → access + refresh token |
| POST | `/api/v1/auth/logout` | login | Logout, semua token dicabut |
| POST | `/api/v1/auth/refresh-token` | publik | Refresh dengan rotation |
| POST | `/api/v1/auth/forgot-password` | publik | Minta token reset |
| POST | `/api/v1/auth/reset-password` | publik | Reset dengan token |
| GET | `/api/v1/auth/me` | login | Profil sendiri |
| GET | `/api/v1/users` | admin | Daftar user + pagination |
| GET | `/api/v1/users/:id` | admin / diri sendiri | Detail user |
| POST | `/api/v1/users` | admin | Buat user |
| PUT | `/api/v1/users/:id` | admin / diri sendiri | Ubah user |
| DELETE | `/api/v1/users/:id` | admin | Hapus user |
| GET | `/api/v1/users/me` | login | Profil sendiri |
| PUT | `/api/v1/users/me/password` | login | Ganti password sendiri |
| GET | `/api/v1/health` | publik | Status + versi + kesehatan DB |

### Contoh

```bash
# login
curl -s -X POST localhost:8081/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"pudin@gmail.com","password":"password-anda"}'

# semua request berikut pakai header
Authorization: Bearer <access_token>

# daftar user
curl -s "localhost:8081/api/v1/users?page=1&limit=10&search=pudin&sort=created_at&order=desc" \
  -H "Authorization: Bearer $TOKEN"
```

### Format respons

```json
{ "success": true,  "message": "Login berhasil", "data": { "...": "..." } }
{ "success": false, "message": "Email atau password salah", "errors": null }
```

Paginasi menambah `meta: {page, limit, total, total_pages}`.
Validasi gagal → `422` dengan `errors: {field: pesan}`.

---

## Perbedaan dari PRD (perbaikan, disengaja)

| PRD | Implementasi | Alasan |
|---|---|---|
| PostgreSQL | **MariaDB/MySQL** | Permintaan eksplisit |
| `updated_et` (typo) | `updated_at` | Typo di skema & trigger |
| ENUM PostgreSQL | `VARCHAR(10)` + CHECK constraint | Portabel MariaDB |
| `token TEXT` (JWT mentah) | `VARCHAR(64)` berisi **SHA-256 refresh token** | JWT mentah di DB = kredensial bocor saat dump |
| `img_profile NOT NULL` tanpa default | default `''` | Insert tidak gagal |
| — | + `must_change_password` | Wajib ganti password pertama (PRD butuh ini) |
| — | + `failed_login_count`, `locked_until` | Lockout brute force |
| — | + `token_version` | Cabut semua access token lama seketika |
| — | + tabel `password_history`, `password_reset_tokens`, `audit_logs` | Anti reuse password, reset flow, jejak keamanan |

---

## Menjalankan di server baru

### 0. Prasyarat
- MariaDB ≥ 10.4 (atau MySQL ≥ 8)
- Tidak perlu Go — binary statis.

### 1. Database
```bash
sudo mysql
```
```sql
CREATE DATABASE go_auth_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER 'myauth'@'localhost' IDENTIFIED BY '<password-kuat>';
GRANT ALL PRIVILEGES ON go_auth_db.* TO 'myauth'@'localhost';
FLUSH PRIVILEGES;
```
Tabel dibuat otomatis saat pertama jalan.

### 2. Binary
```bash
# ambil dari GitHub Release, lalu:
sudo install -m 0755 my-auth-go-linux-amd64 /usr/local/bin/my-auth-go
my-auth-go --version
```

### 3. Environment
```bash
sudo install -d -o root -g myauth -m 750 /etc/my-auth-go
sudo install -d -o myauth -g myauth -m 750 /var/lib/my-auth-go
sudoedit /etc/my-auth-go/my-auth-go.env
```
```bash
PORT=8081
APP_ENV=production

DB_USER=myauth
DB_PASSWORD=<password-db>
DB_HOST=127.0.0.1
DB_PORT=3306
DB_NAME=go_auth_db

# WAJIB: buat sendiri, minimal 32 karakter acak
#   openssl rand -base64 48
JWT_SECRET=<acak-panjang>
ACCESS_TOKEN_EXPIRY=15m
REFRESH_TOKEN_EXPIRY=168h

# Seeder admin pertama — hanya dibuat bila belum ada admin sama sekali.
# Password minimal 12 karakter + huruf besar/kecil/angka/simbol.
# KOSONGKAN setelah login pertama berhasil (dengan mengosongkan nilainya).
ADMIN_EMAIL=pudin@gmail.com
ADMIN_PASSWORD=<password-awal-yang-kuat>
ADMIN_NAME=Pudin Saepudin

VERSI_API=1.0
PUBLIC_BASE_URL=https://api.domain-anda.tld
TRUSTED_PROXIES=127.0.0.1/32,::1/128
LOGIN_RATE_LIMIT=10
MAX_BODY_MB=2
COOKIE_SECURE=true
```

> **Format systemd EnvironmentFile**: tanpa tanda kutip, tanpa spasi di sekitar `=`.
> Password DB dengan karakter khusus tidak perlu di-escape pada file ini karena
> aplikasi membaca env langsung, bukan DSN string.

```bash
sudo chmod 640 /etc/my-auth-go/my-auth-go.env
sudo chown root:myauth /etc/my-auth-go/my-auth-go.env
```

### 4. User sistem
```bash
sudo useradd -r -s /usr/sbin/nologin -d /var/lib/my-auth-go -m myauth
```

### 5. systemd
```bash
sudo cp deploy/my-auth-go.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now my-auth-go
sleep 2
curl -s localhost:8081/api/v1/health
```

### 6. Login pertama
1. `POST /api/v1/auth/login` dengan `ADMIN_EMAIL` + `ADMIN_PASSWORD`
2. Respons `must_change_password: true` → segera `PUT /api/v1/users/me/password`
3. Semua token lama otomatis dicabut
4. Kosongkan `ADMIN_PASSWORD` di env file lalu `systemctl restart my-auth-go`
   agar seeder tidak bisa dipicu ulang.

### Build dari source (opsional)
```bash
make release        # dist/my-auth-go-linux-{amd64,arm64} + SHA256SUMS
make seed           # migrasi + seeder saja
make test           # unit test
```

---

## Keamanan yang sudah diterapkan

- **bcrypt cost 12** + auto-rehash bila hash lama lebih lemah.
- **Anti user-enumeration**: pesan login & forgot-password seragam; timing hash
  dummy saat email tidak dikenal.
- **Refresh token rotation** satu pakai sekali; pemakaian ulang token → semua
  sesi user dicabut (deteksi reuse).
- **`token_version`** di JWT: logout / ganti password / ubah role mematikan
  semua access token lama tanpa menunggu kedaluwarsa.
- **Lockout**: 5 gagal login → akun terkunci 15 menit.
- **Rate limit** endpoint auth per IP (default 10/menit, burst 20).
- **Password baru tidak boleh sama** dengan 5 password terakhir.
- **JWT**: HS256 saja (`WithValidMethods`), issuer dicek, leeway 30 detik,
  tipe access/refresh dipisah ketat.
- **SQL injection**: seluruh query parameterized; kolom sorting lewat allowlist.
- **Security headers**: CSP `default-src 'none'`, nosniff, DENY, no-referrer,
  HSTS (saat HTTPS), `Cache-Control: no-store`.
- **Body limit** 2 MB, header limit 1 MiB, timeout read/write/idle.
- **Audit log**: login, logout, register, refresh, refresh-reuse, reset password
  — semua dengan IP & user agent.
- **Tidak ada rahasia di log**: GORM `ParameterizedQueries=true`, DSN tersamarkan,
  password/token tidak pernah dicetak.
- **Seeder aman**: hanya buat admin bila belum ada admin sama sekali; password
  dari env, bukan source code; wajib ganti setelah login pertama.
- **systemd hardening**: `ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`,
  `MemoryMax=256M`, `SystemCallFilter=@system-service`, user tanpa shell.

## Catatan operasional

- Log JSON via journald: `journalctl -u my-auth-go -f`
- Reset password tanpa email gateway: di `APP_ENV=development` token reset
  ditampilkan di respons `forgot-password` (dengan penanda eksplisit). Di
  produksi sambungkan SMTP — titik integrasinya di `Service.ForgotPassword`.
- Swagger: `http://localhost:8081/swagger/index.html` — hanya di `APP_ENV=development`.
- Health check aman untuk monitoring: `/api/v1/health` tanpa rate limit.
