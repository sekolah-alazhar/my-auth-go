package auth

import (
	"time"

	"github.com/google/uuid"
)

// PasswordResetToken menyimpan permintaan reset password.
// Token disimpan sebagai SHA-256; token mentah hanya dikirim ke pengguna.
type PasswordResetToken struct {
	ID        uuid.UUID  `gorm:"type:char(36);primaryKey" json:"-"`
	UserID    uuid.UUID  `gorm:"type:char(36);not null;index" json:"-"`
	TokenHash string     `gorm:"column:token_hash;type:char(64);not null;uniqueIndex" json:"-"`
	ExpiresAt time.Time  `gorm:"column:expires_at;not null;index" json:"-"`
	UsedAt    *time.Time `gorm:"column:used_at" json:"-"`
	IPAddress string     `gorm:"column:ip_address;type:varchar(45)" json:"-"`
	CreatedAt time.Time  `gorm:"column:created_at;autoCreateTime" json:"-"`
}

// TableName memaksa nama tabel.
func (PasswordResetToken) TableName() string { return "password_reset_tokens" }

// PasswordHistory menyimpan hash password lama untuk mencegah pemakaian ulang.
type PasswordHistory struct {
	ID        uuid.UUID `gorm:"type:char(36);primaryKey" json:"-"`
	UserID    uuid.UUID `gorm:"type:char(36);not null;index" json:"-"`
	Password  string    `gorm:"column:password;type:varchar(255);not null" json:"-"`
	CreatedAt time.Time `gorm:"column:created_at;autoCreateTime" json:"-"`
}

// TableName memaksa nama tabel.
func (PasswordHistory) TableName() string { return "password_history" }

// AuditLog mencatat peristiwa keamanan (login, logout, reset, perubahan data).
type AuditLog struct {
	ID        uint       `gorm:"primaryKey;autoIncrement" json:"id"`
	UserID    *uuid.UUID `gorm:"type:char(36);index" json:"user_id,omitempty"`
	Event     string     `gorm:"column:event;type:varchar(50);not null;index" json:"event"`
	Email     string     `gorm:"column:email;type:varchar(100)" json:"email,omitempty"`
	IPAddress string     `gorm:"column:ip_address;type:varchar(45)" json:"ip_address"`
	UserAgent string     `gorm:"column:user_agent;type:varchar(255)" json:"user_agent"`
	Success   bool       `gorm:"column:success;not null;index" json:"success"`
	Detail    string     `gorm:"column:detail;type:varchar(255)" json:"detail,omitempty"`
	CreatedAt time.Time  `gorm:"column:created_at;autoCreateTime;index" json:"created_at"`
}

// TableName memaksa nama tabel.
func (AuditLog) TableName() string { return "audit_logs" }

// Models dipakai untuk auto-migrate.
func Models() []any {
	return []any{
		&PasswordResetToken{},
		&PasswordHistory{},
		&AuditLog{},
	}
}
