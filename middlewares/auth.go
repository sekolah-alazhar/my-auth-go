// Package middlewares berisi middleware HTTP yang dipakai lintas modul.
package middlewares

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/sekolah-alazhar/my-auth-go/config"
	"github.com/sekolah-alazhar/my-auth-go/modules/users"
	"github.com/sekolah-alazhar/my-auth-go/utils"
)

// Context keys.
const (
	CtxUserID = "user_id"
	CtxRole   = "role"
	CtxEmail  = "email"
)

// Auth memvalidasi access token lalu memuat user dari database.
// Memuat ulang dari DB memastikan akun yang dinonaktifkan atau dihapus
// langsung kehilangan akses, tanpa menunggu token kedaluwarsa.
func Auth(cfg *config.Config, repo *users.Repository, log *slog.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		raw := utils.BearerToken(c)
		if raw == "" {
			utils.Fail(c, http.StatusUnauthorized,
				"Token tidak ditemukan. Sertakan header Authorization: Bearer <token>", nil)
			return
		}

		claims, err := utils.ParseToken(cfg.JWTSecret, raw, utils.TokenAccess)
		if err != nil {
			utils.Fail(c, http.StatusUnauthorized, "Token tidak valid atau kedaluwarsa", nil)
			return
		}

		uid, err := uuid.Parse(claims.UserID)
		if err != nil {
			utils.Fail(c, http.StatusUnauthorized, "Token tidak valid", nil)
			return
		}

		ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
		defer cancel()

		u, err := repo.ByID(ctx, uid)
		if errors.Is(err, users.ErrNotFound) {
			utils.Fail(c, http.StatusUnauthorized, "Akun tidak ditemukan", nil)
			return
		}
		if err != nil {
			log.Error("gagal memuat user untuk otentikasi", "err", err, "uid", uid)
			utils.Fail(c, http.StatusInternalServerError, "Terjadi kesalahan pada server", nil)
			return
		}

		if !u.IsActive() {
			utils.Fail(c, http.StatusForbidden, "Akun tidak aktif", nil)
			return
		}

		// Token diterbitkan sebelum logout/ganti password / perubahan role.
		// Versi token di claims harus sama dengan versi di database.
		if claims.Ver != int64(u.TokenVersion) {
			utils.Fail(c, http.StatusUnauthorized, "Sesi sudah tidak berlaku, silakan login ulang", nil)
			return
		}

		c.Set(CtxUserID, u.ID)
		c.Set(CtxRole, string(u.Role))
		c.Set(CtxEmail, u.Email)
		c.Next()
	}
}

// RequireRole membatasi akses ke role tertentu.
func RequireRole(roles ...string) gin.HandlerFunc {
	allowed := make(map[string]bool, len(roles))
	for _, r := range roles {
		allowed[strings.ToLower(r)] = true
	}
	return func(c *gin.Context) {
		role, _ := c.Get(CtxRole)
		s, _ := role.(string)
		if !allowed[strings.ToLower(s)] {
			utils.Fail(c, http.StatusForbidden, "Tidak memiliki izin untuk mengakses resource ini", nil)
			return
		}
		c.Next()
	}
}
