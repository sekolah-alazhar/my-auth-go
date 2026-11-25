package health

import "github.com/gin-gonic/gin"

// RegisterRoutes mendaftarkan health check pada grup publik.
func RegisterRoutes(r *gin.RouterGroup, h *Controller) {
	r.GET("/health", h.Check)
}
