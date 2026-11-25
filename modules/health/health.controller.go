package health

import (
	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"github.com/sekolah-alazhar/my-auth-go/utils"
)

// Controller menangani health check.
type Controller struct {
	db      *gorm.DB
	version string
	started time.Time
}

// NewController membuat controller health.
func NewController(db *gorm.DB, version string) *Controller {
	return &Controller{db: db, version: version, started: time.Now()}
}

// Check godoc
// @Summary      Health check
// @Description  Menampilkan status aplikasi, versi API, dan kesehatan database.
// @Tags         health
// @Produce      json
// @Success      200 {object} utils.Response{data=health.Status}
// @Failure      503 {object} utils.Response{data=health.Status}
// @Router       /health [get]
func (h *Controller) Check(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 3*time.Second)
	defer cancel()

	st := Status{
		Status:   "ok",
		Version:  h.version,
		Database: "ok",
		Uptime:   time.Since(h.started).Round(time.Second).String(),
		Time:     time.Now().Format(time.RFC3339),
	}

	status := http.StatusOK
	if h.db != nil {
		if sqlDB, err := h.db.DB(); err != nil || sqlDB.PingContext(ctx) != nil {
			st.Status = "degraded"
			st.Database = "down"
			status = http.StatusServiceUnavailable
		}
	}

	c.JSON(status, utils.Response{
		Success: status == http.StatusOK,
		Message: "Aplikasi berjalan",
		Data:    st,
		Errors:  nil,
	})
}

// Status adalah payload health check.
type Status struct {
	Status   string `json:"status" example:"ok"`
	Version  string `json:"version" example:"1.0"`
	Database string `json:"database" example:"ok"`
	Uptime   string `json:"uptime" example:"1h2m3s"`
	Time     string `json:"time" example:"2026-11-25T21:00:00+07:00"`
}
