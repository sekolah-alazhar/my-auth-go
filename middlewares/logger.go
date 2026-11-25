package middlewares

import (
	"log/slog"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// RequestID memberi setiap permintaan ID unik untuk korelasi log.
func RequestID() gin.HandlerFunc {
	return func(c *gin.Context) {
		id := c.GetHeader("X-Request-ID")
		if id == "" {
			id = uuid.NewString()
		}
		c.Set("request_id", id)
		c.Writer.Header().Set("X-Request-ID", id)
		c.Next()
	}
}

// Logger mencatat satu baris per permintaan dalam format terstruktur.
// Password, token, dan body tidak pernah dicatat.
func Logger(log *slog.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		path := c.Request.URL.Path
		query := c.Request.URL.RawQuery

		c.Next()

		status := c.Writer.Status()
		latency := time.Since(start)

		attrs := []any{
			"method", c.Request.Method,
			"path", path,
			"status", status,
			"dur_ms", latency.Milliseconds(),
			"ip", c.ClientIP(),
			"size", c.Writer.Size(),
			"request_id", c.GetString("request_id"),
		}
		if query != "" {
			attrs = append(attrs, "query", query)
		}
		if uid, ok := c.Get(CtxUserID); ok {
			attrs = append(attrs, "user_id", uid)
		}

		switch {
		case status >= 500:
			log.Error("http", attrs...)
		case status >= 400:
			log.Warn("http", attrs...)
		default:
			log.Info("http", attrs...)
		}
	}
}
