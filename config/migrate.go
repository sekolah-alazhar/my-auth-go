package config

import (
	"context"
	"fmt"
	"log/slog"

	"gorm.io/gorm"

	"github.com/sekolah-alazhar/my-auth-go/modules/auth"
	"github.com/sekolah-alazhar/my-auth-go/modules/users"
)

// Migrate menjalankan auto-migrate seluruh model dan menambahkan constraint
// yang tidak bisa diekspresikan lewat tag GORM.
func Migrate(ctx context.Context, db *gorm.DB, log *slog.Logger) error {
	if err := db.WithContext(ctx).AutoMigrate(
		&users.User{},
	); err != nil {
		return fmt.Errorf("migrate tabel users: %w", err)
	}

	models := auth.Models()
	if err := db.WithContext(ctx).AutoMigrate(models...); err != nil {
		return fmt.Errorf("migrate tabel auth: %w", err)
	}

	// CHECK constraint untuk ENUM tiruan (MariaDB 10.2+ mendukung CHECK).
	// Dibuat terpisah dan toleran: bila sudah ada, error diabaikan.
	checks := []string{
		"ALTER TABLE users ADD CONSTRAINT chk_users_role CHECK (role IN ('guest','admin'))",
		"ALTER TABLE users ADD CONSTRAINT chk_users_active CHECK (active IN ('active','inactive'))",
	}
	for _, q := range checks {
		if err := db.WithContext(ctx).Exec(q).Error; err != nil {
			log.Debug("constraint dilewati (mungkin sudah ada)", "constraint", q, "err", err)
		}
	}

	log.Info("migrasi database selesai")
	return nil
}
