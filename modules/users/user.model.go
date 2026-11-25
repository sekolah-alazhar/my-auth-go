package users

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// Role adalah peran user.
type Role string

// Status adalah status akun.
type Status string

const (
	// RoleGuest hanya bisa mengakses data dirinya sendiri.
	RoleGuest Role = "guest"
	// RoleAdmin bisa mengelola seluruh user.
	RoleAdmin Role = "admin"

	// StatusActive akun bisa login.
	StatusActive Status = "active"
	// StatusInactive akun belum/tidak bisa login.
	StatusInactive Status = "inactive"
)

// User adalah baris tabel users.
//
// Catatan perubahan dari PRD (disesuaikan untuk MariaDB + keamanan):
//   - PostgreSQL ENUM → kolom VARCHAR + CHECK constraint (portabel, aman migrasi).
//   - `updated_et` (typo) → `updated_at`.
//   - `img_profile` diberi default kosong agar insert tidak gagal.
//   - `token` dipakai menyimpan SHA-256 refresh token aktif (rotation),
//     bukan JWT mentah.
//   - Tambahan kolom keamanan: must_change_password, failed_login_count,
//     locked_until, last_login_at. Semua punya default sehingga seeder dan
//     query lama tetap jalan.
type User struct {
	ID          uuid.UUID `gorm:"type:char(36);primaryKey" json:"id"`
	NamaLengkap string    `gorm:"column:nama_lengkap;type:varchar(100);not null" json:"nama_lengkap"`
	Email       string    `gorm:"column:email;type:varchar(100);not null;uniqueIndex" json:"email"`
	NoHP        string    `gorm:"column:no_hp;type:varchar(20)" json:"no_hp,omitempty"`
	Password    string    `gorm:"column:password;type:varchar(255);not null" json:"-"`

	// Token menyimpan SHA-256 dari refresh token aktif. NULL/kosong = tidak ada sesi.
	Token  *string `gorm:"column:token;type:varchar(64)" json:"-"`
	Role   Role    `gorm:"column:role;type:varchar(10);not null;default:guest;index" json:"role"`
	Active Status  `gorm:"column:active;type:varchar(10);not null;default:inactive;index" json:"active"`

	ImgProfile string `gorm:"column:img_profile;type:varchar(255);not null;default:''" json:"img_profile"`

	MustChangePassword bool `gorm:"column:must_change_password;not null;default:0" json:"must_change_password"`

	FailedLoginCount int        `gorm:"column:failed_login_count;not null;default:0" json:"-"`
	LockedUntil      *time.Time `gorm:"column:locked_until" json:"-"`
	LastLoginAt      *time.Time `gorm:"column:last_login_at" json:"last_login_at,omitempty"`

	// TokenVersion naik setiap logout/ganti password sehingga semua token lama
	// langsung tidak berlaku walau belum kedaluwarsa.
	TokenVersion int `gorm:"column:token_version;not null;default:0" json:"-"`

	CreatedAt time.Time      `gorm:"column:created_at;autoCreateTime" json:"created_at"`
	UpdatedAt time.Time      `gorm:"column:updated_at;autoUpdateTime" json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"column:deleted_at;index" json:"-"`
}

// TableName memaksa nama tabel tetap `users`.
func (User) TableName() string { return "users" }

// IsAdmin menandai role admin.
func (u *User) IsAdmin() bool { return u.Role == RoleAdmin }

// IsActive menandai akun aktif.
func (u *User) IsActive() bool { return u.Active == StatusActive }

// IsLocked menandai akun terkunci karena percobaan login gagal.
func (u *User) IsLocked(now time.Time) bool {
	return u.LockedUntil != nil && u.LockedUntil.After(now)
}
