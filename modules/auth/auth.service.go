package auth

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/sekolah-alazhar/my-auth-go/exceptions"
	"github.com/sekolah-alazhar/my-auth-go/modules/users"
	"github.com/sekolah-alazhar/my-auth-go/utils"
)

// Service berisi aturan bisnis autentikasi.
type Service struct {
	repo *Repository
	cfg  Options
	log  *slog.Logger
}

// Options adalah konfigurasi yang dibutuhkan service auth.
type Options struct {
	JWTSecret          string
	AccessTokenExpiry  time.Duration
	RefreshTokenExpiry time.Duration
	ResetTokenExpiry   time.Duration
	MaxLoginAttempts   int
	LockDuration       time.Duration
	PasswordHistoryN   int
	PublicBaseURL      string
}

// NewService membuat service auth.
func NewService(repo *Repository, opts Options, log *slog.Logger) *Service {
	if opts.ResetTokenExpiry <= 0 {
		opts.ResetTokenExpiry = time.Hour
	}
	if opts.MaxLoginAttempts <= 0 {
		opts.MaxLoginAttempts = 5
	}
	if opts.LockDuration <= 0 {
		opts.LockDuration = 15 * time.Minute
	}
	if opts.PasswordHistoryN <= 0 {
		opts.PasswordHistoryN = 5
	}
	return &Service{repo: repo, cfg: opts, log: log}
}

// AuditContext adalah metadata permintaan untuk jejak audit.
type AuditContext struct {
	IP        string
	UserAgent string
}

// Register mendaftarkan user baru. Akun baru berstatus inactive dan harus
// diaktifkan admin (sesuai PRD: active default 'inactive').
func (s *Service) Register(ctx context.Context, req RegisterRequest, ac AuditContext) (*users.User, error) {
	if errs := req.Validate(); len(errs) > 0 {
		return nil, exceptions.Unprocessable(describeErrors(errs), errs)
	}

	exists, err := s.repo.userRepo().EmailExists(ctx, req.Email, nil)
	if err != nil {
		return nil, exceptions.Internal(err)
	}
	if exists {
		// Jangan ungkap status email lewat kode berbeda; pesan jelas untuk
		// endpoint registrasi masih dapat diterima (bukan login).
		return nil, exceptions.Conflict("Email sudah terdaftar")
	}

	hash, err := utils.HashPassword(req.Password)
	if err != nil {
		return nil, exceptions.Internal(err)
	}

	u := &users.User{
		ID:                 uuid.New(),
		NamaLengkap:        req.NamaLengkap,
		Email:              req.Email,
		NoHP:               req.NoHP,
		Password:           hash,
		Role:               users.RoleGuest,
		Active:             users.StatusInactive,
		MustChangePassword: false,
	}
	if err := s.repo.userRepo().Create(ctx, u); err != nil {
		return nil, exceptions.Internal(err)
	}

	s.repo.Audit(ctx, &AuditLog{
		UserID:    &u.ID,
		Event:     "register",
		Email:     u.Email,
		IPAddress: ac.IP,
		UserAgent: clip(ac.UserAgent, 255),
		Success:   true,
		Detail:    "akun dibuat, menunggu aktivasi admin",
	})
	s.log.Info("registrasi user", "id", u.ID, "email", u.Email)
	return u, nil
}

// Login memverifikasi kredensial dan menerbitkan sepasang token.
func (s *Service) Login(ctx context.Context, req LoginRequest, ac AuditContext) (*TokenResponse, error) {
	if errs := req.Validate(); len(errs) > 0 {
		return nil, exceptions.Unprocessable(describeErrors(errs), errs)
	}

	// Pesan seragam untuk semua kegagalan kredensial (anti user-enumeration).
	const genericMsg = "Email atau password salah"

	u, err := s.repo.ByEmail(ctx, req.Email)
	if errors.Is(err, users.ErrNotFound) {
		// Jalankan hash dummy agar waktu respons tidak membocorkan keberadaan email.
		_ = utils.VerifyPassword(
			"$2a$12$C6UzMDM.H6dfI/f/IKcEe.7Vt5v7jBSKQ2vYqz6Vqv7Vqz6Vqv7Vq", req.Password)
		s.repo.Audit(ctx, &AuditLog{
			Event: "login", Email: req.Email, IPAddress: ac.IP,
			UserAgent: clip(ac.UserAgent, 255), Success: false, Detail: "email tidak dikenal",
		})
		return nil, exceptions.Unauthorized(genericMsg)
	}
	if err != nil {
		return nil, exceptions.Internal(err)
	}

	if u.IsLocked(time.Now()) {
		s.repo.Audit(ctx, &AuditLog{
			UserID: &u.ID, Event: "login", Email: u.Email, IPAddress: ac.IP,
			UserAgent: clip(ac.UserAgent, 255), Success: false, Detail: "akun terkunci",
		})
		return nil, exceptions.Forbidden("Akun terkunci sementara karena percobaan login gagal. Coba lagi nanti.")
	}

	if !utils.VerifyPassword(u.Password, req.Password) {
		_ = s.repo.userRepo().RegisterFailedLogin(ctx, u.ID, s.cfg.MaxLoginAttempts, s.cfg.LockDuration)
		s.repo.Audit(ctx, &AuditLog{
			UserID: &u.ID, Event: "login", Email: u.Email, IPAddress: ac.IP,
			UserAgent: clip(ac.UserAgent, 255), Success: false, Detail: "password salah",
		})
		return nil, exceptions.Unauthorized(genericMsg)
	}

	if !u.IsActive() {
		s.repo.Audit(ctx, &AuditLog{
			UserID: &u.ID, Event: "login", Email: u.Email, IPAddress: ac.IP,
			UserAgent: clip(ac.UserAgent, 255), Success: false, Detail: "akun belum aktif",
		})
		return nil, exceptions.Forbidden("Akun belum aktif. Hubungi administrator.")
	}

	// Naikkan cost bcrypt bila hash lama memakai cost lebih rendah.
	if utils.NeedsRehash(u.Password) {
		if hash, err := utils.HashPassword(req.Password); err == nil {
			_ = s.repo.userRepo().UpdateFields(ctx, u.ID, map[string]any{"password": hash})
		}
	}

	tokens, refreshHash, err := s.issueTokens(u)
	if err != nil {
		return nil, exceptions.Internal(err)
	}
	// Simpan hash refresh token (rotation: token lama otomatis tidak berlaku).
	if err := s.repo.SaveRefreshToken(ctx, u.ID, &refreshHash); err != nil {
		return nil, exceptions.Internal(err)
	}
	if err := s.repo.userRepo().RegisterSuccessfulLogin(ctx, u.ID); err != nil {
		s.log.Warn("gagal mencatat login sukses", "id", u.ID, "err", err)
	}

	s.repo.Audit(ctx, &AuditLog{
		UserID: &u.ID, Event: "login", Email: u.Email, IPAddress: ac.IP,
		UserAgent: clip(ac.UserAgent, 255), Success: true,
	})
	s.log.Info("login sukses", "id", u.ID, "email", u.Email, "role", u.Role, "ip", ac.IP)
	return tokens, nil
}

// Refresh menukar refresh token lama dengan sepasang token baru (rotation).
func (s *Service) Refresh(ctx context.Context, req RefreshRequest, ac AuditContext) (*TokenResponse, error) {
	if errs := req.Validate(); len(errs) > 0 {
		return nil, exceptions.Unprocessable(describeErrors(errs), errs)
	}

	claims, err := utils.ParseToken(s.cfg.JWTSecret, req.RefreshToken, utils.TokenRefresh)
	if err != nil {
		return nil, exceptions.Unauthorized("Refresh token tidak valid atau kedaluwarsa")
	}

	uid, err := uuid.Parse(claims.UserID)
	if err != nil {
		return nil, exceptions.Unauthorized("Refresh token tidak valid")
	}

	oldHash := utils.HashToken(req.RefreshToken)
	u, err := s.repo.ByRefreshHash(ctx, oldHash)
	if errors.Is(err, users.ErrNotFound) {
		// Token valid secara tanda tangan tapi sudah tidak aktif → kemungkinan
		// dipakai ulang. Cabut semua sesi user sebagai tindakan pengamanan.
		if uu, e := s.repo.ByID(ctx, uid); e == nil {
			_ = s.repo.RevokeRefreshToken(ctx, uu.ID)
			s.repo.Audit(ctx, &AuditLog{
				UserID: &uu.ID, Event: "refresh_reuse", Email: uu.Email,
				IPAddress: ac.IP, UserAgent: clip(ac.UserAgent, 255),
				Success: false, Detail: "refresh token dipakai ulang — semua sesi dicabut",
			})
			s.log.Warn("refresh token dipakai ulang, semua sesi dicabut", "id", uu.ID, "ip", ac.IP)
		}
		return nil, exceptions.Unauthorized("Refresh token tidak valid atau kedaluwarsa")
	}
	if err != nil {
		return nil, exceptions.Internal(err)
	}

	if !u.IsActive() {
		return nil, exceptions.Forbidden("Akun tidak aktif")
	}

	tokens, newHash, err := s.issueTokens(u)
	if err != nil {
		return nil, exceptions.Internal(err)
	}
	if err := s.repo.RotateRefreshToken(ctx, u.ID, oldHash, newHash); err != nil {
		if errors.Is(err, errTokenMismatch) {
			return nil, exceptions.Unauthorized("Refresh token sudah dipakai")
		}
		return nil, exceptions.Internal(err)
	}

	s.repo.Audit(ctx, &AuditLog{
		UserID: &u.ID, Event: "refresh", Email: u.Email, IPAddress: ac.IP,
		UserAgent: clip(ac.UserAgent, 255), Success: true,
	})
	return tokens, nil
}

// Logout mencabut refresh token aktif dan menaikkan versi token.
func (s *Service) Logout(ctx context.Context, userID uuid.UUID, ac AuditContext) error {
	u, err := s.repo.ByID(ctx, userID)
	if err != nil {
		return exceptions.Internal(err)
	}
	if err := s.repo.RevokeRefreshToken(ctx, userID); err != nil {
		return exceptions.Internal(err)
	}
	s.repo.Audit(ctx, &AuditLog{
		UserID: &userID, Event: "logout", Email: u.Email, IPAddress: ac.IP,
		UserAgent: clip(ac.UserAgent, 255), Success: true,
	})
	return nil
}

// ForgotPassword membuat token reset. Selalu mengembalikan sukses agar
// penyerang tidak bisa menebak email mana yang terdaftar.
func (s *Service) ForgotPassword(ctx context.Context, req ForgotPasswordRequest, ac AuditContext) (string, error) {
	if errs := req.Validate(); len(errs) > 0 {
		return "", exceptions.Unprocessable(describeErrors(errs), errs)
	}

	u, err := s.repo.ByEmail(ctx, req.Email)
	if errors.Is(err, users.ErrNotFound) {
		s.repo.Audit(ctx, &AuditLog{
			Event: "forgot_password", Email: req.Email, IPAddress: ac.IP,
			UserAgent: clip(ac.UserAgent, 255), Success: false, Detail: "email tidak dikenal",
		})
		return "", nil // jangan ungkap
	}
	if err != nil {
		return "", exceptions.Internal(err)
	}

	raw, err := utils.RandomToken(32)
	if err != nil {
		return "", exceptions.Internal(err)
	}

	t := &PasswordResetToken{
		ID:        uuid.New(),
		UserID:    u.ID,
		TokenHash: utils.HashToken(raw),
		ExpiresAt: time.Now().Add(s.cfg.ResetTokenExpiry),
		IPAddress: ac.IP,
	}
	if err := s.repo.CreateResetToken(ctx, t); err != nil {
		return "", exceptions.Internal(err)
	}

	s.repo.Audit(ctx, &AuditLog{
		UserID: &u.ID, Event: "forgot_password", Email: u.Email, IPAddress: ac.IP,
		UserAgent: clip(ac.UserAgent, 255), Success: true,
	})
	s.log.Info("permintaan reset password", "id", u.ID, "email", utils.MaskEmail(u.Email))

	// Di produksi nilai ini dikirim lewat email; di sini dikembalikan agar
	// admin bisa meneruskan ke pengguna. TIDAK pernah dicatat ke log.
	return raw, nil
}

// ResetPassword memakai token untuk mengganti password.
func (s *Service) ResetPassword(ctx context.Context, req ResetPasswordRequest, ac AuditContext) error {
	if errs := req.Validate(); len(errs) > 0 {
		return exceptions.Unprocessable(describeErrors(errs), errs)
	}

	t, err := s.repo.ActiveResetToken(ctx, utils.HashToken(req.Token))
	if errors.Is(err, users.ErrNotFound) {
		return exceptions.BadRequest("Token reset tidak valid atau sudah kedaluwarsa", nil)
	}
	if err != nil {
		return exceptions.Internal(err)
	}

	u, err := s.repo.ByID(ctx, t.UserID)
	if err != nil {
		return exceptions.Internal(err)
	}

	// Tolak pemakaian ulang salah satu password terakhir.
	recent, err := s.repo.RecentPasswords(ctx, u.ID, s.cfg.PasswordHistoryN)
	if err != nil {
		return exceptions.Internal(err)
	}
	for _, h := range recent {
		if utils.VerifyPassword(h, req.NewPassword) {
			return exceptions.Unprocessable("Password tidak boleh sama dengan yang pernah dipakai", map[string]string{
				"new_password": "pilih password lain",
			})
		}
	}

	hash, err := utils.HashPassword(req.NewPassword)
	if err != nil {
		return exceptions.Internal(err)
	}
	if err := s.repo.ConsumeResetToken(ctx, t.ID, u.ID, hash); err != nil {
		if errors.Is(err, errTokenMismatch) {
			return exceptions.BadRequest("Token reset sudah dipakai", nil)
		}
		return exceptions.Internal(err)
	}

	s.repo.Audit(ctx, &AuditLog{
		UserID: &u.ID, Event: "reset_password", Email: u.Email, IPAddress: ac.IP,
		UserAgent: clip(ac.UserAgent, 255), Success: true,
	})
	s.log.Info("password direset", "id", u.ID)
	return nil
}

// issueTokens membuat access + refresh token dan hash refresh-nya.
func (s *Service) issueTokens(u *users.User) (*TokenResponse, string, error) {
	access, err := utils.GenerateToken(
		s.cfg.JWTSecret, u.ID, u.Email, string(u.Role),
		utils.TokenAccess, int64(u.TokenVersion), s.cfg.AccessTokenExpiry)
	if err != nil {
		return nil, "", err
	}
	refresh, err := utils.GenerateToken(
		s.cfg.JWTSecret, u.ID, u.Email, string(u.Role),
		utils.TokenRefresh, int64(u.TokenVersion), s.cfg.RefreshTokenExpiry)
	if err != nil {
		return nil, "", err
	}

	return &TokenResponse{
		AccessToken:  access,
		RefreshToken: refresh,
		TokenType:    "Bearer",
		ExpiresIn:    int(s.cfg.AccessTokenExpiry.Seconds()),
		MustChange:   u.MustChangePassword,
	}, utils.HashToken(refresh), nil
}

// CurrentUser mengambil data user yang sedang login.
func (s *Service) CurrentUser(ctx context.Context, id uuid.UUID) (*users.User, error) {
	u, err := s.repo.ByID(ctx, id)
	if errors.Is(err, users.ErrNotFound) {
		return nil, exceptions.NotFound("User tidak ditemukan")
	}
	if err != nil {
		return nil, exceptions.Internal(err)
	}
	return u, nil
}

// clip memotong string ke n byte tanpa memecah rune.
func clip(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	cut := n
	for cut > 0 && (s[cut]&0xC0) == 0x80 {
		cut--
	}
	return s[:cut]
}
