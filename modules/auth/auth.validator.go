package auth

import (
	"net/mail"
	"regexp"
	"strings"

	"github.com/sekolah-alazhar/my-auth-go/utils"
)

// rePhone menerima format Indonesia umum.
var rePhone = regexp.MustCompile(`^(\+62|62|0)[0-9]{8,13}$`)

// RegisterRequest adalah payload pendaftaran.
type RegisterRequest struct {
	NamaLengkap string `json:"nama_lengkap"`
	Email       string `json:"email"`
	NoHP        string `json:"no_hp"`
	Password    string `json:"password"`
}

// LoginRequest adalah payload login.
type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// RefreshRequest adalah payload refresh token.
type RefreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

// ForgotPasswordRequest adalah payload permintaan reset.
type ForgotPasswordRequest struct {
	Email string `json:"email"`
}

// ResetPasswordRequest adalah payload reset password dengan token.
type ResetPasswordRequest struct {
	Token       string `json:"token"`
	NewPassword string `json:"new_password"`
}

// Validate memeriksa RegisterRequest.
func (r *RegisterRequest) Validate() map[string]string {
	errs := map[string]string{}
	r.NamaLengkap = strings.TrimSpace(r.NamaLengkap)
	r.Email = strings.ToLower(strings.TrimSpace(r.Email))
	r.NoHP = normalizePhone(r.NoHP)

	if r.NamaLengkap == "" {
		errs["nama_lengkap"] = "wajib diisi"
	} else if n := len([]rune(r.NamaLengkap)); n < 3 || n > 100 {
		errs["nama_lengkap"] = "panjang 3–100 karakter"
	}
	if msg := validateEmail(r.Email); msg != "" {
		errs["email"] = msg
	}
	if r.NoHP != "" && !rePhone.MatchString(r.NoHP) {
		errs["no_hp"] = "format nomor tidak valid (contoh 08123456789)"
	}
	if problems := utils.PasswordStrength(r.Password); len(problems) > 0 {
		errs["password"] = strings.Join(problems, "; ")
	}
	return errs
}

// Validate memeriksa LoginRequest. Pesan sengaja umum agar tidak
// membocorkan email mana yang terdaftar.
func (r *LoginRequest) Validate() map[string]string {
	errs := map[string]string{}
	r.Email = strings.ToLower(strings.TrimSpace(r.Email))
	if r.Email == "" {
		errs["email"] = "wajib diisi"
	}
	if r.Password == "" {
		errs["password"] = "wajib diisi"
	}
	return errs
}

// Validate memeriksa ForgotPasswordRequest.
func (r *ForgotPasswordRequest) Validate() map[string]string {
	errs := map[string]string{}
	r.Email = strings.ToLower(strings.TrimSpace(r.Email))
	if msg := validateEmail(r.Email); msg != "" {
		errs["email"] = msg
	}
	return errs
}

// Validate memeriksa ResetPasswordRequest.
func (r *ResetPasswordRequest) Validate() map[string]string {
	errs := map[string]string{}
	r.Token = strings.TrimSpace(r.Token)
	if r.Token == "" {
		errs["token"] = "wajib diisi"
	} else if len(r.Token) < 32 {
		errs["token"] = "token tidak valid"
	}
	if problems := utils.PasswordStrength(r.NewPassword); len(problems) > 0 {
		errs["new_password"] = strings.Join(problems, "; ")
	}
	return errs
}

// Validate memeriksa RefreshRequest.
func (r *RefreshRequest) Validate() map[string]string {
	errs := map[string]string{}
	r.RefreshToken = strings.TrimSpace(r.RefreshToken)
	if r.RefreshToken == "" {
		errs["refresh_token"] = "wajib diisi"
	}
	return errs
}

// TokenResponse adalah bentuk data respons login/refresh.
type TokenResponse struct {
	AccessToken  string `json:"access_token" example:"eyJhbGciOi..."`
	RefreshToken string `json:"refresh_token" example:"eyJhbGciOi..."`
	TokenType    string `json:"token_type" example:"Bearer"`
	ExpiresIn    int    `json:"expires_in" example:"900"`
	MustChange   bool   `json:"must_change_password" example:"false"`
}

func validateEmail(email string) string {
	if email == "" {
		return "wajib diisi"
	}
	if len(email) > 100 {
		return "maksimal 100 karakter"
	}
	if _, err := mail.ParseAddress(email); err != nil {
		return "format email tidak valid"
	}
	if !strings.Contains(email, ".") {
		return "format email tidak valid"
	}
	return ""
}

func normalizePhone(s string) string {
	s = strings.TrimSpace(s)
	r := strings.NewReplacer(" ", "", "-", "", ".", "", "(", "", ")", "")
	return r.Replace(s)
}

func describeErrors(errs map[string]string) string {
	if len(errs) == 1 {
		for _, v := range errs {
			return v
		}
	}
	return "beberapa field tidak valid"
}
