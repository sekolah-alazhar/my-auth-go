package utils_test

import (
	"strings"
	"testing"

	"github.com/sekolah-alazhar/my-auth-go/utils"
)

func TestHashAndVerifyPassword(t *testing.T) {
	plain := "Rahasia#Kuat2026"
	hash, err := utils.HashPassword(plain)
	if err != nil {
		t.Fatalf("hash gagal: %v", err)
	}
	if hash == plain {
		t.Fatal("password tersimpan plaintext")
	}
	if !strings.HasPrefix(hash, "$2a$12$") && !strings.HasPrefix(hash, "$2b$12$") {
		t.Errorf("hash bukan bcrypt cost 12: %s", hash[:10])
	}
	if !utils.VerifyPassword(hash, plain) {
		t.Error("password benar ditolak")
	}
	if utils.VerifyPassword(hash, "salah") {
		t.Error("password salah diterima")
	}
}

func TestHashPasswordRejectsShort(t *testing.T) {
	if _, err := utils.HashPassword("pendek"); err == nil {
		t.Error("password pendek seharusnya ditolak")
	}
}

func TestHashPasswordRejectsOver72Bytes(t *testing.T) {
	long := strings.Repeat("a", 73)
	if _, err := utils.HashPassword(long); err == nil {
		t.Error("password >72 byte seharusnya ditolak (bcrypt truncation)")
	}
}

func TestNeedsRehash(t *testing.T) {
	good, _ := utils.HashPassword("Rahasia#Kuat2026")
	if utils.NeedsRehash(good) {
		t.Error("hash cost 12 tidak perlu rehash")
	}
	if !utils.NeedsRehash("bukan-hash") {
		t.Error("hash rusak harus ditandai perlu rehash")
	}
}

func TestPasswordStrength(t *testing.T) {
	cases := []struct {
		name    string
		pass    string
		wantErr bool
	}{
		{"kuat", "Rahasia#Kuat2026", false},
		{"tanpa huruf besar", "rahasia#kuat2026", true},
		{"tanpa angka", "Rahasia#Kuat", true},
		{"tanpa simbol", "RahasiaKuat2026", true},
		{"terlalu pendek", "Ra#1", true},
		{"ada kata password", "Password#2026X", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			problems := utils.PasswordStrength(c.pass)
			if c.wantErr && len(problems) == 0 {
				t.Errorf("password %q seharusnya ditolak", c.pass)
			}
			if !c.wantErr && len(problems) > 0 {
				t.Errorf("password %q seharusnya lolos, dapat: %v", c.pass, problems)
			}
		})
	}
}

func TestTokenHashDeterministic(t *testing.T) {
	tok := "contoh-token-panjang"
	a := utils.HashToken(tok)
	b := utils.HashToken(tok)
	if a != b {
		t.Error("hash token tidak deterministik")
	}
	if len(a) != 64 {
		t.Errorf("hash token harus 64 hex char, dapat %d", len(a))
	}
	if a == tok {
		t.Error("token tersimpan mentah")
	}
	if utils.HashToken("lain") == a {
		t.Error("token berbeda menghasilkan hash sama")
	}
}

func TestRandomTokenUnique(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 100; i++ {
		tok, err := utils.RandomToken(32)
		if err != nil {
			t.Fatalf("gagal: %v", err)
		}
		if len(tok) < 40 {
			t.Errorf("token terlalu pendek: %d", len(tok))
		}
		if seen[tok] {
			t.Fatal("token duplikat")
		}
		seen[tok] = true
	}
}

func TestMaskEmail(t *testing.T) {
	cases := map[string]string{
		"pudin@gmail.com": "p***n@gmail.com",
		"ab@gmail.com":    "a***@gmail.com",
		"a@b.com":         "***",
	}
	for in, want := range cases {
		if got := utils.MaskEmail(in); got != want {
			t.Errorf("MaskEmail(%q) = %q, mau %q", in, got, want)
		}
	}
}

func TestConstantTimeEqual(t *testing.T) {
	if !utils.ConstantTimeEqual("abc", "abc") {
		t.Error("string sama harus true")
	}
	if utils.ConstantTimeEqual("abc", "abd") {
		t.Error("string beda harus false")
	}
}
