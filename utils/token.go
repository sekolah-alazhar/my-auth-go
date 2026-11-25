package utils

import (
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// Claims adalah payload JWT aplikasi.
type Claims struct {
	UserID string `json:"uid"`
	Email  string `json:"email"`
	Role   string `json:"role"`
	// Typ membedakan access vs refresh agar token tidak bisa ditukar pakai.
	Typ string `json:"typ"`
	// Ver adalah versi token; naik tiap logout/ganti password sehingga
	// access token lama langsung ditolak middleware.
	Ver int64 `json:"ver"`
	jwt.RegisteredClaims
}

// TokenKind adalah tipe token yang valid.
type TokenKind string

const (
	// TokenAccess adalah access token jangka pendek.
	TokenAccess TokenKind = "access"
	// TokenRefresh adalah refresh token jangka panjang.
	TokenRefresh TokenKind = "refresh"
)

// GenerateToken membuat JWT bertanda tangan HS256.
func GenerateToken(secret string, uid uuid.UUID, email, role string, kind TokenKind, ver int64, ttl time.Duration) (string, error) {
	now := time.Now()
	claims := Claims{
		UserID: uid.String(),
		Email:  email,
		Role:   role,
		Typ:    string(kind),
		Ver:    ver,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   uid.String(),
			Issuer:    "my-auth-go",
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
			ID:        uuid.NewString(), // jti unik, dipakai audit
		},
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return tok.SignedString([]byte(secret))
}

// ParseToken memvalidasi tanda tangan + masa berlaku + tipe token.
func ParseToken(secret, raw string, want TokenKind) (*Claims, error) {
	claims := &Claims{}
	tok, err := jwt.ParseWithClaims(raw, claims, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("metode tanda tangan tidak diizinkan")
		}
		return []byte(secret), nil
	},
		jwt.WithValidMethods([]string{"HS256"}),
		jwt.WithIssuer("my-auth-go"),
		jwt.WithLeeway(30*time.Second),
	)
	if err != nil {
		return nil, err
	}
	if !tok.Valid {
		return nil, errors.New("token tidak valid")
	}
	if claims.Typ != string(want) {
		return nil, errors.New("tipe token tidak sesuai")
	}
	if claims.UserID == "" {
		return nil, errors.New("token tanpa subject")
	}
	return claims, nil
}

// BearerToken mengambil token dari header Authorization.
func BearerToken(c *gin.Context) string {
	h := c.GetHeader("Authorization")
	if h == "" {
		return ""
	}
	parts := strings.SplitN(h, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return ""
	}
	return strings.TrimSpace(parts[1])
}

// Pagination membaca page/limit dari query dan memberi batas aman.
type Pagination struct {
	Page   int
	Limit  int
	Offset int
}

// ParsePagination mengubah query string jadi Pagination yang aman.
func ParsePagination(c *gin.Context) Pagination {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	if page < 1 {
		page = 1
	}
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "10"))
	if limit < 1 {
		limit = 10
	}
	if limit > 100 {
		limit = 100
	}
	return Pagination{Page: page, Limit: limit, Offset: (page - 1) * limit}
}

// TotalPages menghitung jumlah halaman dari total baris.
func TotalPages(total int64, limit int) int {
	if limit <= 0 {
		return 0
	}
	p := int((total + int64(limit) - 1) / int64(limit))
	if p == 0 && total == 0 {
		return 0
	}
	return p
}

// ResolveSort memetakan sort+order dengan allowlist kolom.
func ResolveSort(sort, order string, allowed map[string]string, defCol string) (string, string) {
	col, ok := allowed[strings.ToLower(strings.TrimSpace(sort))]
	if !ok {
		col = defCol
	}
	dir := "DESC"
	if strings.EqualFold(strings.TrimSpace(order), "asc") {
		dir = "ASC"
	}
	return col, dir
}
