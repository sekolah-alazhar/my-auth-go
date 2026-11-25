package users

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// Repository adalah lapisan akses data untuk tabel users.
type Repository struct {
	db *gorm.DB
}

// NewRepository membuat repository dengan handle GORM.
func NewRepository(db *gorm.DB) *Repository { return &Repository{db: db} }

// ErrNotFound dikembalikan bila baris tidak ada.
var ErrNotFound = errors.New("user tidak ditemukan")

// ListFilter adalah parameter daftar user.
type ListFilter struct {
	Search    string
	Role      string
	Active    string
	SortCol   string
	SortOrder string
	Limit     int
	Offset    int
}

// baseQuery menerapkan filter pencarian.
func (r *Repository) baseQuery(ctx context.Context, f ListFilter) *gorm.DB {
	q := r.db.WithContext(ctx).Model(&User{})
	if s := strings.TrimSpace(f.Search); s != "" {
		like := "%" + escapeLike(s) + "%"
		q = q.Where("(nama_lengkap LIKE ? ESCAPE '\\\\' OR email LIKE ? ESCAPE '\\\\' OR no_hp LIKE ? ESCAPE '\\\\')",
			like, like, like)
	}
	if f.Role != "" {
		q = q.Where("role = ?", f.Role)
	}
	if f.Active != "" {
		q = q.Where("active = ?", f.Active)
	}
	return q
}

// List mengembalikan daftar user + total.
func (r *Repository) List(ctx context.Context, f ListFilter) ([]User, int64, error) {
	var total int64
	if err := r.baseQuery(ctx, f).Count(&total).Error; err != nil {
		return nil, 0, err
	}

	var items []User
	if err := r.baseQuery(ctx, f).
		Order(f.SortCol + " " + f.SortOrder).
		Limit(f.Limit).Offset(f.Offset).
		Find(&items).Error; err != nil {
		return nil, 0, err
	}
	return items, total, nil
}

// ByID mengambil user lewat UUID.
func (r *Repository) ByID(ctx context.Context, id uuid.UUID) (*User, error) {
	var u User
	err := r.db.WithContext(ctx).Where("id = ?", id.String()).First(&u).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &u, nil
}

// ByEmail mengambil user lewat email (case-insensitive karena kolom
// collation utf8mb4_unicode_ci).
func (r *Repository) ByEmail(ctx context.Context, email string) (*User, error) {
	var u User
	err := r.db.WithContext(ctx).Where("email = ?", strings.TrimSpace(email)).First(&u).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &u, nil
}

// ByRefreshHash mencari user yang refresh token aktifnya cocok.
func (r *Repository) ByRefreshHash(ctx context.Context, hash string) (*User, error) {
	var u User
	err := r.db.WithContext(ctx).Where("token = ?", hash).First(&u).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &u, nil
}

// EmailExists memeriksa email dipakai user lain (excludeID opsional).
func (r *Repository) EmailExists(ctx context.Context, email string, excludeID *uuid.UUID) (bool, error) {
	q := r.db.WithContext(ctx).Model(&User{}).Where("email = ?", strings.TrimSpace(email))
	if excludeID != nil {
		q = q.Where("id <> ?", excludeID.String())
	}
	var n int64
	if err := q.Count(&n).Error; err != nil {
		return false, err
	}
	return n > 0, nil
}

// Create menyimpan user baru. UUID dibuat di sini bila kosong.
func (r *Repository) Create(ctx context.Context, u *User) error {
	if u.ID == uuid.Nil {
		u.ID = uuid.New()
	}
	return r.db.WithContext(ctx).Create(u).Error
}

// Update menyimpan perubahan field tertentu.
func (r *Repository) Update(ctx context.Context, u *User) error {
	return r.db.WithContext(ctx).Save(u).Error
}

// UpdateFields mengubah kolom tertentu tanpa menyentuh yang lain.
func (r *Repository) UpdateFields(ctx context.Context, id uuid.UUID, fields map[string]any) error {
	res := r.db.WithContext(ctx).Model(&User{}).Where("id = ?", id.String()).Updates(fields)
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return ErrNotFound
	}
	return nil
}

// Delete melakukan soft delete.
func (r *Repository) Delete(ctx context.Context, id uuid.UUID) error {
	res := r.db.WithContext(ctx).Where("id = ?", id.String()).Delete(&User{})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return ErrNotFound
	}
	return nil
}

// SetRefreshToken menyimpan hash refresh token aktif; nil mengosongkannya.
func (r *Repository) SetRefreshToken(ctx context.Context, id uuid.UUID, hash *string) error {
	return r.db.WithContext(ctx).Model(&User{}).
		Where("id = ?", id.String()).
		Update("token", hash).Error
}

// BumpTokenVersion menaikkan versi token (mencabut semua token lama)
// dan mengosongkan refresh token aktif.
func (r *Repository) BumpTokenVersion(ctx context.Context, id uuid.UUID) error {
	return r.db.WithContext(ctx).Model(&User{}).
		Where("id = ?", id.String()).
		Updates(map[string]any{
			"token_version": gorm.Expr("token_version + 1"),
			"token":         nil,
		}).Error
}

// RegisterFailedLogin menaikkan hitungan gagal dan mengunci bila melewati batas.
func (r *Repository) RegisterFailedLogin(ctx context.Context, id uuid.UUID, maxAttempts int, lockFor time.Duration) error {
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var u User
		if err := tx.Where("id = ?", id.String()).First(&u).Error; err != nil {
			return err
		}
		u.FailedLoginCount++
		fields := map[string]any{"failed_login_count": u.FailedLoginCount}
		if maxAttempts > 0 && u.FailedLoginCount >= maxAttempts {
			fields["locked_until"] = time.Now().Add(lockFor)
			fields["failed_login_count"] = 0
		}
		return tx.Model(&User{}).Where("id = ?", u.ID.String()).Updates(fields).Error
	})
}

// RegisterSuccessfulLogin mengosongkan hitungan gagal dan mencatat waktu login.
func (r *Repository) RegisterSuccessfulLogin(ctx context.Context, id uuid.UUID) error {
	now := time.Now()
	return r.db.WithContext(ctx).Model(&User{}).Where("id = ?", id.String()).
		Updates(map[string]any{
			"failed_login_count": 0,
			"locked_until":       nil,
			"last_login_at":      &now,
		}).Error
}

// escapeLike menetralkan wildcard LIKE dari input pengguna.
func escapeLike(s string) string {
	r := strings.NewReplacer("\\", "\\\\", "%", "\\%", "_", "\\_")
	return r.Replace(s)
}
