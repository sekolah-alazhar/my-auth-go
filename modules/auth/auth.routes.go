package auth

import "github.com/gin-gonic/gin"

// RegisterPublicRoutes mendaftarkan endpoint auth yang tidak butuh token.
func RegisterPublicRoutes(r *gin.RouterGroup, h *Controller) {
	r.POST("/auth/register", h.Register)
	r.POST("/auth/login", h.Login)
	r.POST("/auth/refresh-token", h.Refresh)
	r.POST("/auth/forgot-password", h.ForgotPassword)
	r.POST("/auth/reset-password", h.ResetPassword)
}

// RegisterProtectedRoutes mendaftarkan endpoint auth yang butuh access token.
func RegisterProtectedRoutes(r *gin.RouterGroup, h *Controller) {
	r.POST("/auth/logout", h.Logout)
	r.GET("/auth/me", h.Me)
}
