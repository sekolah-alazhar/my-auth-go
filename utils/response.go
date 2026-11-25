// Package utils berisi helper yang dipakai lintas modul: respons API,
// password, token, paginasi, dan validasi.
package utils

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// Response adalah bentuk standar seluruh respons API.
type Response struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
	Errors  any    `json:"errors"`
	Meta    any    `json:"meta,omitempty"`
}

// Meta adalah metadata paginasi.
type Meta struct {
	Page       int   `json:"page"`
	Limit      int   `json:"limit"`
	Total      int64 `json:"total"`
	TotalPages int   `json:"total_pages"`
}

// OK mengirim 200.
func OK(c *gin.Context, message string, data any) {
	c.JSON(http.StatusOK, Response{Success: true, Message: message, Data: data, Errors: nil})
}

// OKMeta mengirim 200 dengan metadata paginasi.
func OKMeta(c *gin.Context, message string, data any, meta any) {
	c.JSON(http.StatusOK, Response{Success: true, Message: message, Data: data, Errors: nil, Meta: meta})
}

// Created mengirim 201.
func Created(c *gin.Context, message string, data any) {
	c.JSON(http.StatusCreated, Response{Success: true, Message: message, Data: data, Errors: nil})
}

// Fail mengirim respons error standar.
func Fail(c *gin.Context, status int, message string, errs any) {
	c.AbortWithStatusJSON(status, Response{Success: false, Message: message, Errors: errs})
}

// FailValidation mengirim 422 dengan daftar kesalahan per field.
func FailValidation(c *gin.Context, errs map[string]string) {
	Fail(c, http.StatusUnprocessableEntity, "Validasi gagal", errs)
}

// Abort menyimpan respons error tanpa menulis body (dipakai middleware yang
// sudah menulis sendiri). Tidak dipakai langsung oleh handler.
func Abort(c *gin.Context, status int, message string) {
	Fail(c, status, message, nil)
}
