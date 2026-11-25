# PRD Untuk Kebutuhan API Backend User, Login, Logout

PRODUCT REQUIREMENTS DOCUMENT (PRD)
MY AUTH GO — Backend Authentication & User Management API
- Versi Dokumen: 1.0.0
- Status: Final Specification
- Bahasa: Go (Golang)
- Framework: Gin
- Database: PostgreSQL
- Authentication: JWT Access Token + Refresh Token
- API Documentation: Swagger / OpenAPI
- Deployment: Manual (Tanpa Docker)
- Dibuat oleh: Pudin Saepudin

## 1. PROJECT OVERVIEW
### 1.1 Deskripsi Project
My Auth Go adalah aplikasi backend REST API yang dibangun menggunakan bahasa pemrograman Go (Golang) dan framework Gin.

Aplikasi ini bertujuan menyediakan sistem authentication dan user management yang aman, modular, mudah dikembangkan, serta dapat digunakan sebagai fondasi backend untuk berbagai aplikasi lainnya.

Sistem harus mendukung:
- Registrasi pengguna.
- Login dan logout.
- JWT Access Token.
- JWT Refresh Token.
- Refresh token rotation.
- Forgot password.
- Reset password.
- Change password.
- Manajemen user (CRUD).
- Role-based access control (RBAC).
- Middleware authentication dan authorization.
- Validasi request.
- Standarisasi response API.
- Logging dan centralized error handling.
- API documentation menggunakan Swagger.
- Health check.


### 1.2 Tujuan Project
- Membuat backend authentication yang aman dan reusable.
- Mengimplementasikan arsitektur modular menggunakan Go.
- Memisahkan Controller, Service, Repository, dan Validator.
- Menggunakan PostgreSQL sebagai database utama.
- Mengimplementasikan JWT dengan access token dan refresh token.
- Mengimplementasikan role-based access control.
- Menyediakan dokumentasi API yang lengkap.
- Mempermudah pengembangan fitur backend di masa mendatang.


### 1.3 Ruang Lingkup
In Scope
- Authentication.
- Authorization.
- User management.
- Database management.
- Password security.
- JWT management.
- Request validation.
- Error handling.
- API documentation.
- Unit testing.
- Integration testing.
- Manual deployment.


## 1. Struktur Folder
Berikut adalah struktur folder yang harus dibuat
```
my-auth-go/
├── cmd/
│   └── api/
│       └── main.go
├── modules/
│   ├── users/
│   │   ├── user.controller.go
│   │   ├── user.service.go
│   │   ├── user.repository.go
│   │   ├── user.validator.go
│   │   ├── user.model.go
│   │   └── user.routes.go
│   ├── auth/
│   │   ├── auth.controller.go
│   │   ├── auth.service.go
│   │   ├── auth.repository.go
│   │   ├── auth.validator.go
│   │   ├── auth.model.go
│   │   └── auth.routes.go
│   └── health/
│       ├── health.controller.go
│       └── health.routes.go
├── config/
│   └── database.go
├── middlewares/
├── utils/
├── exceptions/
├── routes/
├── docs/
├── tests/
├── .env.example
├── .gitignore
├── go.mod
├── go.sum
├── README.md
└── PRD.md
```

## 2. Struktur Database
Ini adalah struktur table users yang akan dibuat
```
-- Membuat ENUM untuk role
CREATE TYPE user_role AS ENUM ('guest', 'admin');

-- Membuat ENUM untuk status active
CREATE TYPE user_status AS ENUM ('active', 'inactive');

-- Membuat tabel users
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    nama_lengkap VARCHAR(100) NOT NULL,
    email VARCHAR(100) NOT NULL UNIQUE,
    no_hp VARCHAR(20),
    password VARCHAR(255) NOT NULL,
    role user_role NOT NULL DEFAULT 'guest',
    token TEXT NULL,
    active user_status NOT NULL DEFAULT 'inactive',
    img_profile VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_et TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Function untuk update timestamp
CREATE OR REPLACE FUNCTION update_updated_et()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_et = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Trigger otomatis saat UPDATE
CREATE TRIGGER trigger_update_users
BEFORE UPDATE ON users
FOR EACH ROW
EXECUTE FUNCTION update_updated_et();
```
Buatkan email default pudin@gmail.com, passwordnya : Admin#4321, Role : admin, dan active:active untuk saya login pertama.

Data dibuat melalui database seeder, bukan dengan menyimpan password plaintext di SQL.

Ketentuannya:
- Seeder dijalankan saat inisialisasi database.
- Password harus di-hash menggunakan bcrypt.
- Seeder tidak membuat duplikasi jika email sudah ada.
- Akun admin pertama hanya dibuat jika belum tersedia.
- Password awal diambil dari environment variable, bukan ditulis permanen di source code.
- Pengguna diminta mengganti password default setelah login pertama.


## 3. API Endpoint

Berikut pembagian endpoint auth:

| Method | Endpoint | Fungsi |
| --- | --- | --- |
| POST | `/api/v1/auth/register` | Registrasi user |
| POST | `/api/v1/auth/login` | Login user |
| POST | `/api/v1/auth/logout` | Logout user |
| POST | `/api/v1/auth/refresh-token` | Refresh JWT |
| POST | `/api/v1/auth/forgot-password` | Meminta reset password |
| POST | `/api/v1/auth/reset-password` | Reset password |

Berikut pembagian endpoint user:

| Method | Endpoint | Fungsi |
| --- | --- | --- |
| GET | `/api/v1/users` | Tampilkan Semua User |
| GET | `/api/v1/users/(uuid)` | Tampilkan Detail User selain password |
| POST | `/api/v1/users` | Input Data User |
| PUT | `/api/v1/users/(uuid)` | Edit Data User |
| DELETE | `/api/v1/users/(uuid)` | Hapus Data User |

Berikut pembagian endpoint health:

| Method | Endpoint | Fungsi |
| --- | --- | --- |
| GET | `/api/v1/health` | Tampilkan Json Status Sehat Ok dan versi API |

## 4. Contoh config .env
Ini adalah standar config .env yang biasa saya gunakan
```
PORT=8081
DB_USER=root
DB_PASSWORD=password_kamu
DB_HOST=127.0.0.1
DB_PORT=5432
DB_NAME=go_auth_db

JWT_SECRET=SangatRahasia123!
ACCESS_TOKEN_EXPIRY=15m
REFRESH_TOKEN_EXPIRY=168h
VERSI_API=1.0
```

## 5. Standarisasi response API
format response JSON, format konsisten.

Response sukses:
```
{
  "success": true,
  "message": "Login berhasil",
  "data": {
    "access_token": "jwt-token",
    "refresh_token": "refresh-token",
    "token_type": "Bearer",
    "expires_in": 900
  }
}
```
Response error:

```
json
{
  "success": false,
  "message": "Email atau password salah",
  "errors": null
}
```
standar HTTP status code:

- 200: Request berhasil.
- 201: Data berhasil dibuat.
- 400: Request tidak valid.
- 401: Belum terautentikasi.
- 403: Tidak memiliki izin.
- 404: Data tidak ditemukan.
- 409: Konflik data, misalnya email sudah terdaftar.
- 422: Validasi gagal (jika menggunakan konvensi ini).
- 500: Internal server error.

## 6. Pagination, filtering, dan sorting
Endpoint:
```
GET /api/v1/users?page=1&limit=10&search=pudin&sort=created_at&order=desc
```
Response:
```
json
{
  "success": true,
  "message": "Data users berhasil ditemukan",
  "data": [],
  "meta": {
    "page": 1,
    "limit": 10,
    "total": 100,
    "total_pages": 10
  }
}
```
Users tetap efisien ketika jumlah pengguna semakin banyak.

## 7. Gitignor
Jangan commit file .env ke repository, dan usahakan seluruh file sensnitif jangan sampai terupload ke github.

