// Package docs menyediakan dokumentasi OpenAPI (Swagger).
//
// Berkas docs.go, swagger.json, dan swagger.yaml dihasilkan oleh `swag init`.
// Versi di bawah adalah definisi minimal yang selalu bisa dikompilasi walau
// `swag init` belum dijalankan. Jalankan `make swagger` untuk regenerasi
// lengkap dari anotasi di controller.
package docs

// @title           My Auth Go API
// @version         1.0
// @description     Backend authentication & user management (Go + Gin + MariaDB).
// @description     JWT access token + refresh token dengan rotation, RBAC, dan standar respons konsisten.
// @contact.name    Pudin Saepudin
// @host            localhost:8081
// @BasePath        /api/v1
// @schemes         http https
// @securityDefinitions.apikey BearerAuth
// @in              header
// @name            Authorization
// @description     Masukkan "Bearer {access_token}"

// SwaggerInfo menyimpan metadata yang dipakai handler Swagger UI.
type SwaggerInfo struct {
	Version     string
	Host        string
	BasePath    string
	Schemes     []string
	Title       string
	Description string
}

// Info adalah metadata default.
var Info = SwaggerInfo{
	Version:  "1.0",
	Host:     "localhost:8081",
	BasePath: "/api/v1",
	Schemes:  []string{"http", "https"},
	Title:    "My Auth Go API",
	Description: "Backend authentication & user management (Go + Gin + MariaDB). " +
		"JWT access token + refresh token dengan rotation, RBAC, dan standar respons konsisten.",
}

// SwaggerJSON adalah spesifikasi OpenAPI. Diganti oleh `swag init`.
var SwaggerJSON = `{
  "swagger": "2.0",
  "info": {
    "title": "My Auth Go API",
    "version": "1.0",
    "description": "Jalankan 'make swagger' untuk menghasilkan spesifikasi lengkap dari anotasi controller."
  },
  "basePath": "/api/v1",
  "schemes": ["http", "https"],
  "securityDefinitions": {
    "BearerAuth": {
      "type": "apiKey",
      "name": "Authorization",
      "in": "header",
      "description": "Masukkan: Bearer {access_token}"
    }
  },
  "paths": {}
}`

// ReadDoc mengembalikan spesifikasi Swagger sebagai byte.
func ReadDoc() []byte { return []byte(SwaggerJSON) }
