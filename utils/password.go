package utils

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"unicode"

	"golang.org/x/crypto/bcrypt"
)

// BcryptCost dipakai untuk semua hash password user.
const BcryptCost = 12

// HashPassword menghasilkan hash bcrypt.
func HashPassword(plain string) (string, error) {
	if len(plain) < 8 {
		return "", errors.New("password minimal 8 karakter")
	}
	// bcrypt memotong input > 72 byte; tolak agar tidak ada karakter hilang diam-diam.
	if len([]byte(plain)) > 72 {
		return "", errors.New("password maksimal 72 byte")
	}
	h, err := bcrypt.GenerateFromPassword([]byte(plain), BcryptCost)
	if err != nil {
		return "", err
	}
	return string(h), nil
}

// VerifyPassword membandingkan hash dengan plaintext.
func VerifyPassword(hash, plain string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(plain)) == nil
}

// NeedsRehash menandai hash dengan cost lebih rendah dari standar.
func NeedsRehash(hash string) bool {
	cost, err := bcrypt.Cost([]byte(hash))
	return err != nil || cost < BcryptCost
}

// PasswordStrength memeriksa syarat minimal password.
// Mengembalikan daftar pelanggaran; kosong berarti lolos.
func PasswordStrength(p string) []string {
	var problems []string
	if len(p) < 12 {
		problems = append(problems, "minimal 12 karakter")
	}
	if len([]byte(p)) > 72 {
		problems = append(problems, "maksimal 72 byte")
	}
	var upper, lower, digit, symbol bool
	for _, r := range p {
		switch {
		case unicode.IsUpper(r):
			upper = true
		case unicode.IsLower(r):
			lower = true
		case unicode.IsDigit(r):
			digit = true
		case unicode.IsPunct(r) || unicode.IsSymbol(r):
			symbol = true
		}
	}
	if !upper {
		problems = append(problems, "harus ada huruf besar")
	}
	if !lower {
		problems = append(problems, "harus ada huruf kecil")
	}
	if !digit {
		problems = append(problems, "harus ada angka")
	}
	if !symbol {
		problems = append(problems, "harus ada simbol")
	}
	if strings.Contains(strings.ToLower(p), "password") {
		problems = append(problems, "tidak boleh memuat kata 'password'")
	}
	return problems
}

// RandomToken menghasilkan token acak base64url sepanjang n byte entropi.
func RandomToken(nBytes int) (string, error) {
	b := make([]byte, nBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// HashToken menyimpan token sebagai SHA-256 hex — token mentah tidak pernah
// masuk database.
func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// ConstantTimeEqual membandingkan dua string tanpa membocorkan waktu.
func ConstantTimeEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// MaskEmail menyamarkan email untuk pesan yang tampil ke publik.
func MaskEmail(email string) string {
	at := strings.IndexByte(email, '@')
	if at <= 1 {
		return "***"
	}
	name, domain := email[:at], email[at:]
	if len(name) <= 2 {
		return string(name[0]) + "***" + domain
	}
	return string(name[0]) + strings.Repeat("*", len(name)-2) + string(name[len(name)-1]) + domain
}
