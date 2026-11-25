package config

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/sekolah-alazhar/my-auth-go/modules/users"
	"github.com/sekolah-alazhar/my-auth-go/utils"
)

// SeederResult menjelaskan apa yang dilakukan seeder.
type SeederResult struct {
	Created bool
	Email   string
	Skipped bool
}

// Seed membuat akun admin pertama bila belum ada.
//
// Aturan (sesuai PRD):
//   - Dijalankan saat inisialisasi database.
//   - Password di-hash bcrypt, tidak pernah plaintext di SQL.
//   - Tidak membuat duplikasi bila email sudah ada.
//   - Akun admin pertama hanya dibuat bila belum ada admin sama sekali.
//   - Password awal berasal dari environment, bukan hardcode.
//   - Admin wajib mengganti password setelah login pertama.
func Seed(ctx context.Context, db *gorm.DB, c *Config, log *slog.Logger) (*SeederResult, error) {
	if c.AdminEmail == "" || c.AdminPassword == "" {
		log.Info("seeder dilewati: ADMIN_EMAIL/ADMIN_PASSWORD tidak diisi")
		return &SeederResult{Skipped: true}, nil
	}
	if err := validateSeedInput(c); err != nil {
		return nil, err
	}

	// Sudah ada admin? jangan buat lagi.
	var adminCount int64
	if err := db.WithContext(ctx).Model(&users.User{}).
		Where("role = ?", users.RoleAdmin).Count(&adminCount).Error; err != nil {
		return nil, fmt.Errorf("hitung admin: %w", err)
	}
	if adminCount > 0 {
		log.Info("seeder dilewati: sudah ada admin", "jumlah", adminCount)
		return &SeederResult{Skipped: true, Email: c.AdminEmail}, nil
	}

	// Email sudah dipakai akun non-admin? Jangan ubah diam-diam.
	var existing users.User
	err := db.WithContext(ctx).Where("email = ?", c.AdminEmail).First(&existing).Error
	if err == nil {
		// Promosikan akun yang ada menjadi admin aktif, tanpa menyentuh password.
		if err := db.WithContext(ctx).Model(&users.User{}).
			Where("id = ?", existing.ID.String()).
			Updates(map[string]any{
				"role":                 users.RoleAdmin,
				"active":               users.StatusActive,
				"must_change_password": true,
			}).Error; err != nil {
			return nil, fmt.Errorf("promosikan admin: %w", err)
		}
		log.Warn("akun dengan email admin sudah ada, dipromosikan menjadi admin aktif",
			"email", c.AdminEmail)
		return &SeederResult{Created: true, Email: c.AdminEmail}, nil
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, fmt.Errorf("periksa email admin: %w", err)
	}

	hash, err := utils.HashPassword(c.AdminPassword)
	if err != nil {
		return nil, fmt.Errorf("hash password admin: %w", err)
	}

	admin := &users.User{
		ID:                 uuid.New(),
		NamaLengkap:        c.AdminName,
		Email:              c.AdminEmail,
		NoHP:               c.AdminPhone,
		Password:           hash,
		Role:               users.RoleAdmin,
		Active:             users.StatusActive,
		MustChangePassword: true, // wajib ganti setelah login pertama
	}
	if err := db.WithContext(ctx).Create(admin).Error; err != nil {
		return nil, fmt.Errorf("buat admin: %w", err)
	}

	log.Info("admin pertama dibuat; wajib ganti password setelah login",
		"email", c.AdminEmail, "id", admin.ID)
	return &SeederResult{Created: true, Email: c.AdminEmail}, nil
}

// validateSeedInput memastikan kredensial awal tidak lemah.
func validateSeedInput(c *Config) error {
	if problems := utils.PasswordStrength(c.AdminPassword); len(problems) > 0 {
		return fmt.Errorf("ADMIN_PASSWORD tidak memenuhi syarat: %v", problems)
	}
	if c.AdminEmail == "" || !containsAt(c.AdminEmail) {
		return fmt.Errorf("ADMIN_EMAIL tidak valid")
	}
	return nil
}

func containsAt(s string) bool {
	for _, r := range s {
		if r == '@' {
			return true
		}
	}
	return false
}
