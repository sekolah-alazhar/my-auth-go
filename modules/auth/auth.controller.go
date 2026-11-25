package auth

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/sekolah-alazhar/my-auth-go/utils"
)

// Controller menangani HTTP untuk modul auth.
type Controller struct {
	svc *Service
	cfg *ControllerConfig
}

// ControllerConfig berisi opsi yang memengaruhi respons HTTP.
type ControllerConfig struct {
	// ExposeResetToken mengembalikan token reset di body respons
	// (hanya untuk lingkungan non-produksi tanpa email gateway).
	ExposeResetToken bool
	// IsProduction mengaktifkan cookie Secure.
	IsProduction bool
}

// NewController membuat controller auth.
func NewController(svc *Service, cfg *ControllerConfig) *Controller {
	if cfg == nil {
		cfg = &ControllerConfig{}
	}
	return &Controller{svc: svc, cfg: cfg}
}

// auditCtx menyusun metadata audit dari permintaan.
func auditCtx(c *gin.Context) AuditContext {
	return AuditContext{IP: c.ClientIP(), UserAgent: c.Request.UserAgent()}
}

// Register godoc
// @Summary      Registrasi user
// @Description  Mendaftarkan akun baru. Akun berstatus inactive dan harus diaktifkan admin sebelum bisa login.
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        body  body  auth.RegisterRequest  true  "Data pendaftaran"
// @Success      201 {object} utils.Response{data=auth.RegisterResponse}
// @Failure      409 {object} exceptions.Response
// @Failure      422 {object} exceptions.Response
// @Router       /auth/register [post]
func (h *Controller) Register(c *gin.Context) {
	var req RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.Fail(c, http.StatusBadRequest, "Body JSON tidak valid", map[string]string{
			"body": "format JSON tidak sesuai",
		})
		return
	}

	u, err := h.svc.Register(c.Request.Context(), req, auditCtx(c))
	if err != nil {
		_ = c.Error(err)
		return
	}

	utils.Created(c, "Registrasi berhasil, akun menunggu aktivasi administrator", RegisterResponse{
		ID:     u.ID.String(),
		Nama:   u.NamaLengkap,
		Email:  u.Email,
		Active: string(u.Active),
	})
}

// Login godoc
// @Summary      Login
// @Description  Memverifikasi kredensial dan menerbitkan access + refresh token. Refresh token dirotasi setiap kali dipakai.
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        body  body  auth.LoginRequest  true  "Email & password"
// @Success      200 {object} utils.Response{data=auth.TokenResponse}
// @Failure      401 {object} exceptions.Response
// @Failure      403 {object} exceptions.Response
// @Router       /auth/login [post]
func (h *Controller) Login(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.Fail(c, http.StatusBadRequest, "Body JSON tidak valid", nil)
		return
	}

	tokens, err := h.svc.Login(c.Request.Context(), req, auditCtx(c))
	if err != nil {
		_ = c.Error(err)
		return
	}
	utils.OK(c, "Login berhasil", tokens)
}

// Refresh godoc
// @Summary      Refresh token
// @Description  Menukar refresh token dengan pasangan token baru. Refresh token lama langsung tidak berlaku (rotation).
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        body  body  auth.RefreshRequest  true  "Refresh token"
// @Success      200 {object} utils.Response{data=auth.TokenResponse}
// @Failure      401 {object} exceptions.Response
// @Router       /auth/refresh-token [post]
func (h *Controller) Refresh(c *gin.Context) {
	var req RefreshRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.Fail(c, http.StatusBadRequest, "Body JSON tidak valid", nil)
		return
	}

	tokens, err := h.svc.Refresh(c.Request.Context(), req, auditCtx(c))
	if err != nil {
		_ = c.Error(err)
		return
	}
	utils.OK(c, "Token berhasil diperbarui", tokens)
}

// Logout godoc
// @Summary      Logout
// @Description  Mencabut refresh token aktif dan menaikkan versi token sehingga semua access token lama tidak berlaku.
// @Tags         auth
// @Produce      json
// @Security     BearerAuth
// @Success      200 {object} utils.Response
// @Failure      401 {object} exceptions.Response
// @Router       /auth/logout [post]
func (h *Controller) Logout(c *gin.Context) {
	uid := userIDFrom(c)
	if uid == uuid.Nil {
		utils.Fail(c, http.StatusUnauthorized, "Belum terautentikasi", nil)
		return
	}
	if err := h.svc.Logout(c.Request.Context(), uid, auditCtx(c)); err != nil {
		_ = c.Error(err)
		return
	}
	utils.OK(c, "Logout berhasil", nil)
}

// ForgotPassword godoc
// @Summary      Lupa password
// @Description  Mengirim token reset bila email terdaftar. Respons selalu sama agar email tidak bisa ditebak.
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        body  body  auth.ForgotPasswordRequest  true  "Email terdaftar"
// @Success      200 {object} utils.Response{data=auth.ForgotPasswordResponse}
// @Failure      422 {object} exceptions.Response
// @Router       /auth/forgot-password [post]
func (h *Controller) ForgotPassword(c *gin.Context) {
	var req ForgotPasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.Fail(c, http.StatusBadRequest, "Body JSON tidak valid", nil)
		return
	}

	token, err := h.svc.ForgotPassword(c.Request.Context(), req, auditCtx(c))
	if err != nil {
		_ = c.Error(err)
		return
	}

	resp := ForgotPasswordResponse{
		Message: "Jika email terdaftar, tautan reset password sudah dikirim.",
	}
	// Token hanya ditampilkan bila eksplisit diizinkan (lingkungan non-produksi
	// tanpa layanan email). Di produksi token dikirim lewat email.
	if h.cfg.ExposeResetToken && token != "" {
		resp.ResetToken = token
		resp.ExpiresIn = int((60 * 60 * 1000) / 1000)
		resp.Note = "Mode pengembangan: token ditampilkan karena belum ada pengiriman email."
	}
	utils.OK(c, resp.Message, resp)
}

// ResetPassword godoc
// @Summary      Reset password
// @Description  Mengganti password memakai token dari forgot-password. Semua sesi lama dicabut.
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        body  body  auth.ResetPasswordRequest  true  "Token & password baru"
// @Success      200 {object} utils.Response
// @Failure      400 {object} exceptions.Response
// @Failure      422 {object} exceptions.Response
// @Router       /auth/reset-password [post]
func (h *Controller) ResetPassword(c *gin.Context) {
	var req ResetPasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.Fail(c, http.StatusBadRequest, "Body JSON tidak valid", nil)
		return
	}
	if err := h.svc.ResetPassword(c.Request.Context(), req, auditCtx(c)); err != nil {
		_ = c.Error(err)
		return
	}
	utils.OK(c, "Password berhasil direset, silakan login dengan password baru", nil)
}

// Me godoc
// @Summary      Profil sendiri
// @Description  Menampilkan data user yang sedang login.
// @Tags         auth
// @Produce      json
// @Security     BearerAuth
// @Success      200 {object} utils.Response
// @Failure      401 {object} exceptions.Response
// @Router       /auth/me [get]
func (h *Controller) Me(c *gin.Context) {
	uid := userIDFrom(c)
	u, err := h.svc.CurrentUser(c.Request.Context(), uid)
	if err != nil {
		_ = c.Error(err)
		return
	}
	utils.OK(c, "Profil user", u)
}

// RegisterResponse adalah data respons registrasi.
type RegisterResponse struct {
	ID     string `json:"id"`
	Nama   string `json:"nama_lengkap"`
	Email  string `json:"email"`
	Active string `json:"active"`
}

// ForgotPasswordResponse adalah data respons forgot-password.
type ForgotPasswordResponse struct {
	Message    string `json:"message"`
	ResetToken string `json:"reset_token,omitempty"`
	ExpiresIn  int    `json:"expires_in,omitempty"`
	Note       string `json:"note,omitempty"`
}

func userIDFrom(c *gin.Context) uuid.UUID {
	v, ok := c.Get("user_id")
	if !ok {
		return uuid.Nil
	}
	switch t := v.(type) {
	case uuid.UUID:
		return t
	case string:
		id, err := uuid.Parse(t)
		if err != nil {
			return uuid.Nil
		}
		return id
	}
	return uuid.Nil
}
