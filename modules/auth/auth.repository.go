package auth

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/sekolah-alazhar/my-auth-go/modules/users"
)

// Repository menyediakan akses data khusus autentikasi.
type Repository struct {
	db *gorm.DB
}

// NewRepository membuat repository auth.
func NewRepository(db *gorm.DB) *Repository { return &Repository{db: db} }

// userRepo membungkus akses tabel users agar tidak duplikasi query.
func (r *Repository) userRepo() *users.Repository {
	return users.NewRepository(r.db)
}

// ByEmail mengambil user berdasarkan email.
func (r *Repository) ByEmail(ctx context.Context, email string) (*users.User, error) {
	return r.userRepo().ByEmail(ctx, email)
}

// ByID mengambil user berdasarkan id.
func (r *Repository) ByID(ctx context.Context, id uuid.UUID) (*users.User, error) {
	return r.userRepo().ByID(ctx, id)
}

// SaveRefreshToken menyimpan hash refresh token aktif.
func (r *Repository) SaveRefreshToken(ctx context.Context, id uuid.UUID, hash *string) error {
	return r.userRepo().SetRefreshToken(ctx, id, hash)
}

// ByRefreshHash mencari user dari hash refresh token aktif.
func (r *Repository) ByRefreshHash(ctx context.Context, hash string) (*users.User, error) {
	return r.userRepo().ByRefreshHash(ctx, hash)
}

// RotateRefreshToken mengganti hash refresh token lama dengan yang baru dalam
// satu transaksi. Gagal bila hash lama sudah tidak cocok (token dipakai ulang).
func (r *Repository) RotateRefreshToken(ctx context.Context, id uuid.UUID, oldHash, newHash string) error {
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		res := tx.Model(&users.User{}).
			Where("id = ? AND token = ?", id.String(), oldHash).
			Update("token", newHash)
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			return errTokenMismatch
		}
		return nil
	})
}

// RevokeRefreshToken mengosongkan refresh token (logout).
func (r *Repository) RevokeRefreshToken(ctx context.Context, id uuid.UUID) error {
	return r.db.WithContext(ctx).Model(&users.User{}).
		Where("id = ?", id.String()).
		Updates(map[string]any{"token": nil, "token_version": gorm.Expr("token_version + 1")}).Error
}

// CreateResetToken menyimpan token reset password baru.
// Token lama milik user yang sama ditandai tidak berlaku.
func (r *Repository) CreateResetToken(ctx context.Context, t *PasswordResetToken) error {
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		now := time.Now()
		if err := tx.Model(&PasswordResetToken{}).
			Where("user_id = ? AND used_at IS NULL", t.UserID.String()).
			Update("used_at", &now).Error; err != nil {
			return err
		}
		return tx.Create(t).Error
	})
}

// ActiveResetToken mencari token reset yang belum dipakai dan belum kedaluwarsa.
func (r *Repository) ActiveResetToken(ctx context.Context, tokenHash string) (*PasswordResetToken, error) {
	var t PasswordResetToken
	err := r.db.WithContext(ctx).
		Where("token_hash = ? AND used_at IS NULL AND expires_at > ?", tokenHash, time.Now()).
		First(&t).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, users.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &t, nil
}

// ConsumeResetToken menandai token terpakai, mengganti password user, dan
// mencabut semua sesi — dalam satu transaksi.
func (r *Repository) ConsumeResetToken(ctx context.Context, tokenID, userID uuid.UUID, newHash string) error {
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		now := time.Now()
		res := tx.Model(&PasswordResetToken{}).
			Where("id = ? AND used_at IS NULL", tokenID.String()).
			Update("used_at", &now)
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			return errTokenMismatch
		}

		if err := tx.Model(&users.User{}).Where("id = ?", userID.String()).
			Updates(map[string]any{
				"password":             newHash,
				"must_change_password": false,
				"token":                nil,
				"token_version":        gorm.Expr("token_version + 1"),
				"failed_login_count":   0,
				"locked_until":         nil,
			}).Error; err != nil {
			return err
		}

		return tx.Create(&PasswordHistory{
			ID:       uuid.New(),
			UserID:   userID,
			Password: newHash,
		}).Error
	})
}

// AddPasswordHistory menyimpan hash password ke riwayat.
func (r *Repository) AddPasswordHistory(ctx context.Context, userID uuid.UUID, hash string) error {
	return r.db.WithContext(ctx).Create(&PasswordHistory{
		ID:       uuid.New(),
		UserID:   userID,
		Password: hash,
	}).Error
}

// RecentPasswords mengambil n hash password terakhir milik user.
func (r *Repository) RecentPasswords(ctx context.Context, userID uuid.UUID, n int) ([]string, error) {
	var rows []PasswordHistory
	if err := r.db.WithContext(ctx).
		Where("user_id = ?", userID.String()).
		Order("created_at DESC").Limit(n).
		Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		out = append(out, r.Password)
	}
	return out, nil
}

// Audit menyimpan jejak peristiwa keamanan.
func (r *Repository) Audit(ctx context.Context, a *AuditLog) {
	// Kegagalan audit tidak boleh menggagalkan permintaan pengguna.
	_ = r.db.WithContext(ctx).Create(a).Error
}

// errTokenMismatch menandai token sudah tidak berlaku.
var errTokenMismatch = errors.New("token tidak lagi berlaku")
