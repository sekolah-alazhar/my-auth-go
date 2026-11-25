package users

import "github.com/gin-gonic/gin"

// RegisterAdminRoutes mendaftarkan endpoint manajemen user (khusus admin).
func RegisterAdminRoutes(rg *gin.RouterGroup, h *Controller) {
	rg.GET("/users", h.List)
	rg.GET("/users/:id", h.Get)
	rg.POST("/users", h.Create)
	rg.PUT("/users/:id", h.Update)
	rg.DELETE("/users/:id", h.Delete)
}

// RegisterSelfRoutes mendaftarkan endpoint untuk user yang login (semua role).
func RegisterSelfRoutes(rg *gin.RouterGroup, h *Controller) {
	// /users/me/password harus lebih dulu agar tidak tertangkap /users/:id.
	rg.PUT("/users/me/password", h.ChangePassword)
	rg.GET("/users/me", h.Me)
}
