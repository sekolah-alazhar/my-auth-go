package users

import (
	"context"
	"errors"
	"log/slog"
	"strings"

	"github.com/google/uuid"

	"github.com/sekolah-alazhar/my-auth-go/exceptions"
	"github.com/sekolah-alazhar/my-auth-go/utils"
)

// Service berisi aturan bisnis manajemen user.
type Service struct {
	repo *Repository
	log  *slog.Logger
}

// NewService membuat service user.
func NewService(repo *Repository, log *slog.Logger) *Service {
	return &Service{repo: repo, log: log}
}

// List mengembalikan daftar user dengan paginasi.
func (s *Service) List(ctx context.Context, f ListFilter) ([]User, int64, error) {
	items, total, err := s.repo.List(ctx, f)
	if err != nil {
		return nil, 0, exceptions.Internal(err)
	}
	return items, total, nil
}

// Get mengambil satu user.
func (s *Service) Get(ctx context.Context, id uuid.UUID) (*User, error) {
	u, err := s.repo.ByID(ctx, id)
	if errors.Is(err, ErrNotFound) {
		return nil, exceptions.NotFound("User tidak ditemukan")
	}
	if err != nil {
		return nil, exceptions.Internal(err)
	}
	return u, nil
}

// Create membuat user baru (dipakai admin lewat POST /users).
func (s *Service) Create(ctx context.Context, req CreateRequest) (*User, error) {
	if errs := req.Validate(); len(errs) > 0 {
		return nil, exceptions.Unprocessable(describeErrors(errs), errs)
	}
	if req.Password == "" {
		return nil, exceptions.Unprocessable("Validasi gagal", map[string]string{
			"password": "wajib diisi saat membuat user baru",
		})
	}

	exists, err := s.repo.EmailExists(ctx, req.Email, nil)
	if err != nil {
		return nil, exceptions.Internal(err)
	}
	if exists {
		return nil, exceptions.Conflict("Email sudah terdaftar")
	}

	hash, err := utils.HashPassword(req.Password)
	if err != nil {
		return nil, exceptions.Internal(err)
	}

	u := &User{
		ID:          uuid.New(),
		NamaLengkap: req.NamaLengkap,
		Email:       req.Email,
		NoHP:        req.NoHP,
		Password:    hash,
		Role:        roleOrDefault(req.Role),
		Active:      statusOrDefault(req.Active),
		ImgProfile:  req.ImgProfile,
		// Password dibuat oleh admin → user wajib menggantinya sendiri.
		MustChangePassword: true,
	}
	if err := s.repo.Create(ctx, u); err != nil {
		if isDuplicate(err) {
			return nil, exceptions.Conflict("Email sudah terdaftar")
		}
		return nil, exceptions.Internal(err)
	}

	s.log.Info("user dibuat", "id", u.ID, "email", u.Email, "role", u.Role)
	return u, nil
}

// Update mengubah data user. Hanya field yang dikirim yang diubah.
func (s *Service) Update(ctx context.Context, id uuid.UUID, req UpdateRequest) (*User, error) {
	if errs := req.Validate(); len(errs) > 0 {
		return nil, exceptions.Unprocessable(describeErrors(errs), errs)
	}

	u, err := s.repo.ByID(ctx, id)
	if errors.Is(err, ErrNotFound) {
		return nil, exceptions.NotFound("User tidak ditemukan")
	}
	if err != nil {
		return nil, exceptions.Internal(err)
	}

	fields := map[string]any{}

	if req.NamaLengkap != nil {
		fields["nama_lengkap"] = strings.TrimSpace(*req.NamaLengkap)
	}
	if req.NoHP != nil {
		fields["no_hp"] = normalizePhone(*req.NoHP)
	}
	if req.ImgProfile != nil {
		fields["img_profile"] = *req.ImgProfile
	}
	if req.Email != nil {
		email := strings.ToLower(strings.TrimSpace(*req.Email))
		if email != u.Email {
			exists, err := s.repo.EmailExists(ctx, email, &id)
			if err != nil {
				return nil, exceptions.Internal(err)
			}
			if exists {
				return nil, exceptions.Conflict("Email sudah terdaftar")
			}
			fields["email"] = email
			// Email berubah → sesi lama dicabut karena identitas berubah.
			fields["token"] = nil
			fields["token_version"] = gormExprIncrement()
		}
	}
	if req.Role != nil {
		role := roleOrDefault(*req.Role)
		// Admin terakhir tidak boleh diturunkan jadi guest.
		if u.Role == RoleAdmin && role != RoleAdmin {
			n, err := s.countAdmins(ctx, u.ID)
			if err != nil {
				return nil, exceptions.Internal(err)
			}
			if n == 0 {
				return nil, exceptions.Conflict("Tidak bisa menurunkan admin terakhir")
			}
		}
		fields["role"] = role
		fields["token_version"] = gormExprIncrement()
	}
	if req.Active != nil {
		status := statusOrDefault(*req.Active)
		if u.Active == StatusActive && status != StatusActive {
			if u.Role == RoleAdmin {
				n, err := s.countAdmins(ctx, u.ID)
				if err != nil {
					return nil, exceptions.Internal(err)
				}
				if n == 0 {
					return nil, exceptions.Conflict("Tidak bisa menonaktifkan admin terakhir")
				}
			}
			fields["token"] = nil // nonaktif → sesi dicabut
		}
		fields["active"] = status
	}
	if req.Password != nil && *req.Password != "" {
		hash, err := utils.HashPassword(*req.Password)
		if err != nil {
			return nil, exceptions.Internal(err)
		}
		fields["password"] = hash
		fields["token"] = nil
		fields["token_version"] = gormExprIncrement()
		fields["must_change_password"] = true
	}

	if len(fields) == 0 {
		return u, nil
	}
	if err := s.repo.UpdateFields(ctx, id, fields); err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil, exceptions.NotFound("User tidak ditemukan")
		}
		if isDuplicate(err) {
			return nil, exceptions.Conflict("Email sudah terdaftar")
		}
		return nil, exceptions.Internal(err)
	}

	updated, err := s.repo.ByID(ctx, id)
	if err != nil {
		return nil, exceptions.Internal(err)
	}
	s.log.Info("user diubah", "id", id, "oleh_admin", true, "field", fieldNames(fields))
	return updated, nil
}

// Delete menghapus user (soft delete).
func (s *Service) Delete(ctx context.Context, id, actorID uuid.UUID) error {
	if id == actorID {
		return exceptions.Conflict("Tidak bisa menghapus akun sendiri")
	}
	u, err := s.repo.ByID(ctx, id)
	if errors.Is(err, ErrNotFound) {
		return exceptions.NotFound("User tidak ditemukan")
	}
	if err != nil {
		return exceptions.Internal(err)
	}
	if u.Role == RoleAdmin {
		n, err := s.countAdmins(ctx, u.ID)
		if err != nil {
			return exceptions.Internal(err)
		}
		if n == 0 {
			return exceptions.Conflict("Tidak bisa menghapus admin terakhir")
		}
	}
	if err := s.repo.Delete(ctx, id); err != nil {
		if errors.Is(err, ErrNotFound) {
			return exceptions.NotFound("User tidak ditemukan")
		}
		return exceptions.Internal(err)
	}
	s.log.Info("user dihapus", "id", id, "aktor", actorID)
	return nil
}

// ChangePassword mengganti password milik sendiri.
func (s *Service) ChangePassword(ctx context.Context, id uuid.UUID, oldPass, newPass string) error {
	if oldPass == "" || newPass == "" {
		return exceptions.Unprocessable("Validasi gagal", map[string]string{
			"old_password": "wajib diisi",
			"new_password": "wajib diisi",
		})
	}
	if oldPass == newPass {
		return exceptions.Unprocessable("Validasi gagal", map[string]string{
			"new_password": "password baru harus berbeda dari yang lama",
		})
	}
	if problems := utils.PasswordStrength(newPass); len(problems) > 0 {
		return exceptions.Unprocessable("Password baru terlalu lemah", map[string]string{
			"new_password": strings.Join(problems, "; "),
		})
	}

	u, err := s.repo.ByID(ctx, id)
	if err != nil {
		return exceptions.Internal(err)
	}
	if !utils.VerifyPassword(u.Password, oldPass) {
		return exceptions.Unauthorized("Password lama salah")
	}

	hash, err := utils.HashPassword(newPass)
	if err != nil {
		return exceptions.Internal(err)
	}
	err = s.repo.UpdateFields(ctx, id, map[string]any{
		"password":             hash,
		"must_change_password": false,
		"token":                nil,
		"token_version":        gormExprIncrement(),
	})
	if err != nil {
		return exceptions.Internal(err)
	}
	s.log.Info("password diganti", "id", id)
	return nil
}

// countAdmins menghitung admin aktif selain excludeID.
func (s *Service) countAdmins(ctx context.Context, excludeID uuid.UUID) (int64, error) {
	items, total, err := s.repo.List(ctx, ListFilter{
		Role:   string(RoleAdmin),
		Active: string(StatusActive),
		Limit:  100,
		Offset: 0,
		// sort diisi agar query valid
		SortCol: "created_at", SortOrder: "ASC",
	})
	if err != nil {
		return 0, err
	}
	var n int64
	for i := range items {
		if items[i].ID != excludeID {
			n++
		}
	}
	_ = total
	return n, nil
}

// fieldNames mengembalikan nama field untuk log (tanpa nilai).
func fieldNames(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
