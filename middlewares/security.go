package middlewares

import (
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/time/rate"

	"github.com/sekolah-alazhar/my-auth-go/utils"
)

// RateLimit membatasi jumlah permintaan per IP per menit.
// Token bucket per IP dengan pembersihan berkala agar map tidak bocor memori.
func RateLimit(perMinute int, burst int) gin.HandlerFunc {
	if perMinute <= 0 {
		perMinute = 60
	}
	if burst <= 0 {
		burst = perMinute
	}

	type entry struct {
		lim  *rate.Limiter
		seen time.Time
	}

	var (
		mu       sync.Mutex
		buckets  = make(map[string]*entry)
		lastGC   = time.Now()
		gcPeriod = 10 * time.Minute
	)

	// Pembersihan bucket yang tidak dipakai > 30 menit.
	cleanup := func(now time.Time) {
		if now.Sub(lastGC) < gcPeriod {
			return
		}
		for k, v := range buckets {
			if now.Sub(v.seen) > 30*time.Minute {
				delete(buckets, k)
			}
		}
		lastGC = now
	}

	return func(c *gin.Context) {
		ip := c.ClientIP()
		now := time.Now()

		mu.Lock()
		cleanup(now)
		e, ok := buckets[ip]
		if !ok {
			e = &entry{lim: rate.NewLimiter(rate.Limit(float64(perMinute)/60.0), burst)}
			buckets[ip] = e
		}
		e.seen = now
		allowed := e.lim.Allow()
		mu.Unlock()

		if !allowed {
			c.Header("Retry-After", "60")
			utils.Fail(c, http.StatusTooManyRequests, "Terlalu banyak permintaan. Coba lagi beberapa saat lagi.", nil)
			return
		}
		c.Next()
	}
}

// SecurityHeaders memasang header keamanan standar.
// Dipasang sebelum handler agar berlaku di semua respons, termasuk error.
func SecurityHeaders() gin.HandlerFunc {
	return func(c *gin.Context) {
		h := c.Writer.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("X-XSS-Protection", "0") // usang; CSP yang menangani
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
		h.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		h.Set("Cache-Control", "no-store")

		// HSTS hanya bermakna di HTTPS.
		if c.Request.TLS != nil || strings.EqualFold(c.GetHeader("X-Forwarded-Proto"), "https") {
			h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}

		if c.Request.Method == http.MethodHead || c.Request.Method == http.MethodOptions {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}
		c.Next()
	}
}

// MaxBody membatasi ukuran body permintaan agar tidak bisa dipakai
// menghabiskan memori.
func MaxBody(limit int64) gin.HandlerFunc {
	return func(c *gin.Context) {
		if limit <= 0 {
			limit = 1 << 20
		}
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, limit)
		c.Next()
	}
}

// CORS mengizinkan origin tertentu (bukan wildcard) dengan kredensial.
// Bila allowedOrigins kosong, CORS tidak mengirim header apa pun.
func CORS(allowedOrigins []string) gin.HandlerFunc {
	allowed := make(map[string]bool, len(allowedOrigins))
	for _, o := range allowedOrigins {
		allowed[strings.TrimRight(o, "/")] = true
	}

	return func(c *gin.Context) {
		origin := strings.TrimRight(c.GetHeader("Origin"), "/")
		if origin != "" && allowed[origin] {
			h := c.Writer.Header()
			h.Set("Access-Control-Allow-Origin", origin)
			h.Set("Access-Control-Allow-Credentials", "true")
			h.Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
			h.Set("Access-Control-Allow-Headers", "Authorization, Content-Type, Accept, X-Requested-With")
			h.Set("Access-Control-Expose-Headers", "X-Request-ID")
			h.Set("Access-Control-Max-Age", "600")
			h.Add("Vary", "Origin")
		}

		if c.Request.Method == http.MethodOptions {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}
		c.Next()
	}
}
