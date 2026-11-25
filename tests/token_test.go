package utils_test

import (
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/sekolah-alazhar/my-auth-go/utils"
)

const testSecret = "rahasia-uji-yang-cukup-panjang-32-char"

func TestGenerateAndParseAccessToken(t *testing.T) {
	uid := uuid.New()
	raw, err := utils.GenerateToken(testSecret, uid, "pudin@gmail.com", "admin",
		utils.TokenAccess, 0, 15*time.Minute)
	if err != nil {
		t.Fatalf("generate gagal: %v", err)
	}

	claims, err := utils.ParseToken(testSecret, raw, utils.TokenAccess)
	if err != nil {
		t.Fatalf("parse gagal: %v", err)
	}
	if claims.UserID != uid.String() {
		t.Errorf("uid = %q, mau %q", claims.UserID, uid)
	}
	if claims.Email != "pudin@gmail.com" {
		t.Errorf("email = %q", claims.Email)
	}
	if claims.Role != "admin" {
		t.Errorf("role = %q", claims.Role)
	}
	if claims.Typ != "access" {
		t.Errorf("typ = %q", claims.Typ)
	}
}

func TestParseTokenRejectsWrongKind(t *testing.T) {
	uid := uuid.New()
	access, _ := utils.GenerateToken(testSecret, uid, "a@b.com", "guest", utils.TokenAccess, 0, time.Minute)

	// Access token tidak boleh dipakai sebagai refresh token.
	if _, err := utils.ParseToken(testSecret, access, utils.TokenRefresh); err == nil {
		t.Error("access token diterima sebagai refresh token")
	}
}

func TestParseTokenRejectsWrongSecret(t *testing.T) {
	uid := uuid.New()
	raw, _ := utils.GenerateToken(testSecret, uid, "a@b.com", "guest", utils.TokenAccess, 0, time.Minute)

	if _, err := utils.ParseToken("secret-yang-berbeda-total-32-chars", raw, utils.TokenAccess); err == nil {
		t.Error("token dengan secret salah diterima")
	}
}

func TestParseTokenRejectsExpired(t *testing.T) {
	uid := uuid.New()
	// TTL negatif → sudah kedaluwarsa.
	raw, err := utils.GenerateToken(testSecret, uid, "a@b.com", "guest", utils.TokenAccess, 0, -time.Minute)
	if err != nil {
		t.Fatalf("generate gagal: %v", err)
	}

	if _, err := utils.ParseToken(testSecret, raw, utils.TokenAccess); err == nil {
		t.Error("token kedaluwarsa diterima")
	}
}

func TestParseTokenRejectsGarbage(t *testing.T) {
	for _, bad := range []string{"", "abc", "a.b.c", "Bearer xyz"} {
		if _, err := utils.ParseToken(testSecret, bad, utils.TokenAccess); err == nil {
			t.Errorf("token sampah %q diterima", bad)
		}
	}
}

func TestParseTokenRejectsAlgNone(t *testing.T) {
	// Token dengan alg:none harus ditolak (ditolak oleh WithValidMethods).
	noneToken := "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1aWQiOiJhYmMiLCJ0eXAiOiJhY2Nlc3MifQ."
	if _, err := utils.ParseToken(testSecret, noneToken, utils.TokenAccess); err == nil {
		t.Error("token alg=none diterima")
	}
}

func TestPaginationBounds(t *testing.T) {
	// Table-driven lewat struct langsung (ParsePagination butuh *gin.Context;
	// diuji di integration test). Di sini cukup TotalPages.
	cases := []struct {
		total int64
		limit int
		want  int
	}{
		{0, 10, 0},
		{1, 10, 1},
		{10, 10, 1},
		{11, 10, 2},
		{100, 10, 10},
		{101, 10, 11},
		{5, 0, 0},
	}
	for _, c := range cases {
		if got := utils.TotalPages(c.total, c.limit); got != c.want {
			t.Errorf("TotalPages(%d,%d) = %d, mau %d", c.total, c.limit, got, c.want)
		}
	}
}

func TestResolveSort(t *testing.T) {
	allowed := map[string]string{
		"created_at": "created_at",
		"email":      "email",
	}

	col, dir := utils.ResolveSort("email", "asc", allowed, "created_at")
	if col != "email" || dir != "ASC" {
		t.Errorf("dapat %q %q", col, dir)
	}

	// Kolom tidak dikenal → fallback, TIDAK diteruskan ke SQL.
	col, dir = utils.ResolveSort("password; DROP TABLE users", "desc", allowed, "created_at")
	if col != "created_at" || dir != "DESC" {
		t.Errorf("injeksi lolos: %q %q", col, dir)
	}
}

func TestParseTokenCarriesVersion(t *testing.T) {
	uid := uuid.New()
	raw, _ := utils.GenerateToken(testSecret, uid, "a@b.com", "guest", utils.TokenAccess, 3, time.Minute)
	claims, err := utils.ParseToken(testSecret, raw, utils.TokenAccess)
	if err != nil {
		t.Fatalf("parse gagal: %v", err)
	}
	if claims.Ver != 3 {
		t.Errorf("ver = %d, mau 3", claims.Ver)
	}
}
