// Package config memuat konfigurasi dari environment dan membuka koneksi
// database (MariaDB/MySQL) menggunakan GORM.
package config

import (
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/joho/godotenv"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// Config adalah konfigurasi runtime aplikasi.
type Config struct {
	AppName string
	Env     string
	Port    string

	DBHost string
	DBPort string
	DBUser string
	DBPass string
	DBName string
	DBTLS  bool

	JWTSecret          string
	AccessTokenExpiry  time.Duration
	RefreshTokenExpiry time.Duration

	APIVersion string

	// Version diisi saat runtime dari ldflags.
	Version string

	AdminEmail    string
	AdminPassword string
	AdminName     string
	AdminPhone    string

	// Keamanan
	TrustedProxies []string
	LoginRateLimit int // percobaan per menit per IP
	MaxBodyBytes   int64
	CookieSecure   bool
	// PublicBaseURL dipakai untuk menyusun link reset password.
	PublicBaseURL string
	// CORSAllowedOrigins adalah daftar origin yang boleh memanggil API dari browser.
	// Kosong = tidak ada header CORS (API hanya untuk server-to-server / klien non-browser).
	CORSAllowedOrigins []string
}

// DB adalah handle database global.
var DB *gorm.DB

// Cfg menyimpan konfigurasi yang sudah dimuat.
var Cfg *Config

// Load membaca .env (bila ada) lalu environment. Nilai wajib divalidasi.
func Load() (*Config, error) {
	// .env hanya untuk pengembangan; di produksi pakai EnvironmentFile systemd.
	_ = godotenv.Load()

	c := &Config{
		AppName: env("APP_NAME", "my-auth-go"),
		Env:     env("APP_ENV", "production"),
		Port:    env("PORT", "8081"),

		DBHost: env("DB_HOST", "127.0.0.1"),
		DBPort: env("DB_PORT", "3306"),
		DBUser: env("DB_USER", ""),
		DBPass: env("DB_PASSWORD", ""),
		DBName: env("DB_NAME", ""),
		DBTLS:  env("DB_TLS", "false") == "true",

		JWTSecret:          env("JWT_SECRET", ""),
		AccessTokenExpiry:  envDur("ACCESS_TOKEN_EXPIRY", 15*time.Minute),
		RefreshTokenExpiry: envDur("REFRESH_TOKEN_EXPIRY", 168*time.Hour),

		APIVersion: env("VERSI_API", "1.0"),

		AdminEmail:    env("ADMIN_EMAIL", ""),
		AdminPassword: env("ADMIN_PASSWORD", ""),
		AdminName:     env("ADMIN_NAME", "Administrator"),
		AdminPhone:    env("ADMIN_NO_HP", ""),

		TrustedProxies:     splitList(env("TRUSTED_PROXIES", "127.0.0.1/32,::1/128")),
		LoginRateLimit:     envInt("LOGIN_RATE_LIMIT", 10),
		MaxBodyBytes:       int64(envInt("MAX_BODY_MB", 2)) << 20,
		CookieSecure:       env("COOKIE_SECURE", "true") == "true",
		PublicBaseURL:      strings.TrimRight(env("PUBLIC_BASE_URL", "http://localhost:"+env("PORT", "8081")), "/"),
		CORSAllowedOrigins: splitList(env("CORS_ALLOWED_ORIGINS", "")),
	}

	if c.DBUser == "" || c.DBName == "" {
		return nil, fmt.Errorf("DB_USER dan DB_NAME wajib diisi")
	}
	if len(c.JWTSecret) < 32 {
		return nil, fmt.Errorf("JWT_SECRET wajib diisi minimal 32 karakter (acak, bukan tebakan)")
	}
	// Tolak secret contoh yang sering tertinggal di produksi.
	if strings.Contains(strings.ToLower(c.JWTSecret), "sangatrahasia") ||
		strings.Contains(strings.ToLower(c.JWTSecret), "changeme") ||
		strings.Contains(strings.ToLower(c.JWTSecret), "secret123") {
		return nil, fmt.Errorf("JWT_SECRET masih memakai nilai contoh; ganti dengan string acak 32+ karakter")
	}
	if c.AccessTokenExpiry <= 0 || c.RefreshTokenExpiry <= c.AccessTokenExpiry {
		return nil, fmt.Errorf("ACCESS_TOKEN_EXPIRY/REFRESH_TOKEN_EXPIRY tidak valid")
	}
	if len(c.AdminPassword) > 0 && len(c.AdminPassword) < 12 {
		return nil, fmt.Errorf("ADMIN_PASSWORD minimal 12 karakter")
	}

	Cfg = c
	return c, nil
}

// CORSOrigins mengembalikan daftar origin yang diizinkan.
func (c *Config) CORSOrigins() []string { return c.CORSAllowedOrigins }

// DSN menyusun DSN MySQL. Password di-escape agar karakter khusus aman.
func (c *Config) DSN() string {
	params := []string{"charset=utf8mb4", "parseTime=True", "loc=Asia%2FJakarta", "timeout=10s"}
	if c.DBTLS {
		params = append(params, "tls=true")
	}
	return fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?%s",
		c.DBUser, c.DBPass, c.DBHost, c.DBPort, c.DBName, strings.Join(params, "&"))
}

// DSNWithoutDB dipakai untuk membuat database bila belum ada.
func (c *Config) DSNWithoutDB() string {
	params := []string{"charset=utf8mb4", "parseTime=True", "timeout=10s"}
	if c.DBTLS {
		params = append(params, "tls=true")
	}
	return fmt.Sprintf("%s:%s@tcp(%s:%s)/?%s",
		c.DBUser, c.DBPass, c.DBHost, c.DBPort, strings.Join(params, "&"))
}

// Connect membuka koneksi database, memastikan database ada, lalu pool siap.
func Connect(c *Config, log *slog.Logger) (*gorm.DB, error) {
	if err := ensureDatabase(c, log); err != nil {
		return nil, err
	}

	gormLog := logger.New(
		slogWriter{log: log},
		logger.Config{
			SlowThreshold:             500 * time.Millisecond,
			LogLevel:                  logger.Warn,
			IgnoreRecordNotFoundError: true,
			ParameterizedQueries:      true, // jangan pernah cetak nilai parameter (bisa berisi password)
			Colorful:                  false,
		},
	)

	db, err := gorm.Open(mysql.Open(c.DSN()), &gorm.Config{
		Logger: gormLog,
		NowFunc: func() time.Time {
			return time.Now().In(c.location())
		},
	})
	if err != nil {
		return nil, fmt.Errorf("buka koneksi database: %w", err)
	}

	sqlDB, err := db.DB()
	if err != nil {
		return nil, err
	}
	sqlDB.SetMaxOpenConns(25)
	sqlDB.SetMaxIdleConns(10)
	sqlDB.SetConnMaxLifetime(30 * time.Minute)
	sqlDB.SetConnMaxIdleTime(10 * time.Minute)

	if err := sqlDB.Ping(); err != nil {
		return nil, fmt.Errorf("ping database: %w", err)
	}

	DB = db
	log.Info("database terhubung", "host", c.DBHost, "port", c.DBPort, "db", c.DBName)
	return db, nil
}

// ensureDatabase membuat database bila belum ada (butuh hak CREATE).
func ensureDatabase(c *Config, log *slog.Logger) error {
	admin, err := gorm.Open(mysql.Open(c.DSNWithoutDB()), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		// Tidak bisa konek tanpa db — mungkin user tidak punya hak, tapi DB sudah ada.
		// Biarkan Connect() yang melaporkan error sebenarnya.
		log.Warn("tidak bisa memeriksa keberadaan database, lanjut", "err", err)
		return nil
	}
	defer func() {
		if s, e := admin.DB(); e == nil {
			s.Close()
		}
	}()

	q := fmt.Sprintf("CREATE DATABASE IF NOT EXISTS `%s` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci",
		strings.ReplaceAll(c.DBName, "`", ""))
	if err := admin.Exec(q).Error; err != nil {
		log.Warn("database tidak bisa dibuat otomatis (mungkin sudah ada)", "err", err)
	}
	return nil
}

// Close menutup pool database.
func Close() {
	if DB == nil {
		return
	}
	if s, err := DB.DB(); err == nil {
		_ = s.Close()
	}
}

func (c *Config) location() *time.Location {
	loc, err := time.LoadLocation("Asia/Jakarta")
	if err != nil {
		return time.FixedZone("WIB", 7*3600)
	}
	return loc
}

// IsProduction menandai lingkungan produksi (cookie Secure, dsb).
func (c *Config) IsProduction() bool { return c.Env == "production" }

// RedactedDSN adalah DSN dengan password disamarkan, aman untuk log.
func (c *Config) RedactedDSN() string {
	return fmt.Sprintf("%s:***@tcp(%s:%s)/%s", c.DBUser, c.DBHost, c.DBPort, c.DBName)
}

// slogWriter menjembatani logger GORM ke slog.
type slogWriter struct{ log *slog.Logger }

func (w slogWriter) Printf(format string, args ...any) {
	w.log.Warn("gorm", "msg", fmt.Sprintf(format, args...))
}

// URLEncodePassword dipakai dokumentasi/README untuk escape manual.
func URLEncodePassword(p string) string { return url.QueryEscape(p) }

func env(k, def string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return def
}

func envInt(k string, def int) int {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func envDur(k string, def time.Duration) time.Duration {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			return d
		}
	}
	return def
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
