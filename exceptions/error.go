// Package exceptions menyatukan tipe error aplikasi dan middleware
// centralized error handling.
package exceptions

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"runtime/debug"

	"github.com/gin-gonic/gin"
)

// AppError adalah error yang membawa status HTTP dan pesan aman untuk client.
type AppError struct {
	Status  int
	Message string
	Errors  any
	// Err adalah error asli; hanya dicatat di log, tidak dikirim ke client.
	Err error
}

func (e *AppError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %v", e.Message, e.Err)
	}
	return e.Message
}

func (e *AppError) Unwrap() error { return e.Err }

// New membuat AppError.
func New(status int, message string, errs any) *AppError {
	return &AppError{Status: status, Message: message, Errors: errs}
}

// Wrap membuat AppError dengan error asli untuk log.
func Wrap(status int, message string, err error) *AppError {
	return &AppError{Status: status, Message: message, Err: err}
}

// Konstruktor yang sering dipakai.
func BadRequest(msg string, errs any) *AppError { return New(http.StatusBadRequest, msg, errs) }
func Unauthorized(msg string) *AppError         { return New(http.StatusUnauthorized, msg, nil) }
func Forbidden(msg string) *AppError            { return New(http.StatusForbidden, msg, nil) }
func NotFound(msg string) *AppError             { return New(http.StatusNotFound, msg, nil) }
func Conflict(msg string) *AppError             { return New(http.StatusConflict, msg, nil) }
func Unprocessable(msg string, errs any) *AppError {
	return New(http.StatusUnprocessableEntity, msg, errs)
}
func Internal(err error) *AppError {
	return &AppError{Status: http.StatusInternalServerError, Message: "Terjadi kesalahan pada server", Err: err}
}

// Response adalah bentuk respons error standar.
type Response struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
	Errors  any    `json:"errors"`
}

// Recovery menangkap panic dan mengubahnya jadi 500 yang rapi tanpa
// membocorkan stack trace ke client.
func Recovery(log *slog.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		defer func() {
			if r := recover(); r != nil {
				log.Error("panic tertangkap",
					"err", fmt.Sprint(r),
					"path", c.Request.URL.Path,
					"method", c.Request.Method,
					"ip", c.ClientIP(),
					"stack", string(debug.Stack()),
				)
				c.AbortWithStatusJSON(http.StatusInternalServerError, Response{
					Success: false,
					Message: "Terjadi kesalahan pada server",
					Errors:  nil,
				})
			}
		}()
		c.Next()
	}
}

// Handle mengubah error hasil handler menjadi respons JSON.
// Handler memanggil c.Error(err) lalu return; middleware ini yang menulis body.
func Handle(log *slog.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next()
		if len(c.Errors) == 0 {
			return
		}

		err := c.Errors.Last().Err
		var appErr *AppError
		if errors.As(err, &appErr) {
			if appErr.Err != nil {
				log.Warn("permintaan gagal",
					"status", appErr.Status,
					"path", c.Request.URL.Path,
					"method", c.Request.Method,
					"err", appErr.Err,
				)
			}
			if !c.Writer.Written() {
				c.JSON(appErr.Status, Response{
					Success: false,
					Message: appErr.Message,
					Errors:  appErr.Errors,
				})
			}
			return
		}

		log.Error("error tak tertangani",
			"path", c.Request.URL.Path,
			"method", c.Request.Method,
			"err", err,
		)
		if !c.Writer.Written() {
			c.JSON(http.StatusInternalServerError, Response{
				Success: false,
				Message: "Terjadi kesalahan pada server",
				Errors:  nil,
			})
		}
	}
}
