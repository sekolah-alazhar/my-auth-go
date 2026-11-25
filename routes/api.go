// Package routes menyusun seluruh router dan dependency aplikasi.
package routes

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"github.com/sekolah-alazhar/my-auth-go/config"
	"github.com/sekolah-alazhar/my-auth-go/exceptions"
	"github.com/sekolah-alazhar/my-auth-go/middlewares"
	"github.com/sekolah-alazhar/my-auth-go/modules/auth"
	"github.com/sekolah-alazhar/my-auth-go/modules/health"
	"github.com/sekolah-alazhar/my-auth-go/modules/users"
	"github.com/sekolah-alazhar/my-auth-go/utils"
)

// Options mengatur pembuatan router.
type Options struct {
	Config  *config.Config
	DB      *gorm.DB
	Log     *slog.Logger
	Version string
	// ExposeResetToken menampilkan token reset di respons forgot-password
	// (hanya untuk lingkungan tanpa email gateway).
	ExposeResetToken bool
}

// New menyusun router lengkap beserta seluruh dependency.
func New(opts Options) *gin.Engine {
	cfg := opts.Config
	log := opts.Log

	if cfg.IsProduction() {
		gin.SetMode(gin.ReleaseMode)
	}

	r := gin.New()
	r.RedirectTrailingSlash = false
	r.HandleMethodNotAllowed = true
	r.MaxMultipartMemory = 4 << 20 // 4 MiB

	// Hanya proxy yang dideklarasikan dipercaya, agar ClientIP tidak bisa dipalsukan
	// lewat header X-Forwarded-For.
	if err := r.SetTrustedProxies(cfg.TrustedProxies); err != nil {
		log.Warn("trusted proxies tidak valid, memakai default aman", "err", err)
		_ = r.SetTrustedProxies([]string{"127.0.0.1/32", "::1/128"})
	}

	// Middleware global — urutan penting.
	r.Use(middlewares.RequestID())
	r.Use(middlewares.Logger(log))
	r.Use(exceptions.Recovery(log))
	r.Use(middlewares.SecurityHeaders())
	r.Use(middlewares.MaxBody(cfg.MaxBodyBytes))
	r.Use(middlewares.CORS(cfg.CORSOrigins()))
	r.Use(exceptions.Handle(log))

	// Dependency graph.
	userRepo := users.NewRepository(opts.DB)
	userSvc := users.NewService(userRepo, log)
	userCtrl := users.NewController(userSvc)

	authRepo := auth.NewRepository(opts.DB)
	authSvc := auth.NewService(authRepo, auth.Options{
		JWTSecret:          cfg.JWTSecret,
		AccessTokenExpiry:  cfg.AccessTokenExpiry,
		RefreshTokenExpiry: cfg.RefreshTokenExpiry,
		ResetTokenExpiry:   60 * time.Minute,
		MaxLoginAttempts:   5,
		LockDuration:       15 * time.Minute,
		PasswordHistoryN:   5,
		PublicBaseURL:      cfg.PublicBaseURL,
	}, log)
	authCtrl := auth.NewController(authSvc, &auth.ControllerConfig{
		ExposeResetToken: opts.ExposeResetToken,
		IsProduction:     cfg.IsProduction(),
	})

	healthCtrl := health.NewController(opts.DB, opts.Version)

	v1 := r.Group("/api/v1")

	// Health tanpa rate limit agar monitoring tidak terganggu.
	health.RegisterRoutes(v1, healthCtrl)

	// Auth publik dengan rate limit per IP.
	public := v1.Group("")
	public.Use(middlewares.RateLimit(cfg.LoginRateLimit, cfg.LoginRateLimit*2))
	auth.RegisterPublicRoutes(public, authCtrl)

	// Grup terautentikasi.
	protected := v1.Group("")
	protected.Use(middlewares.Auth(cfg, userRepo, log))
	auth.RegisterProtectedRoutes(protected, authCtrl)
	users.RegisterSelfRoutes(protected, userCtrl)

	// Manajemen user: khusus admin.
	admin := protected.Group("")
	admin.Use(middlewares.RequireRole(string(users.RoleAdmin)))
	users.RegisterAdminRoutes(admin, userCtrl)

	// 404 & 405 konsisten dengan format respons standar.
	r.NoRoute(func(c *gin.Context) {
		utils.Fail(c, http.StatusNotFound, "Endpoint tidak ditemukan", nil)
	})
	r.NoMethod(func(c *gin.Context) {
		utils.Fail(c, http.StatusMethodNotAllowed, "Method tidak diizinkan untuk endpoint ini", nil)
	})

	return r
}
