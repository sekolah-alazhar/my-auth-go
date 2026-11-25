package users

import (
	"fmt"
	"net/mail"
	"regexp"
	"strings"
)

// rePhone menerima format Indonesia umum: +62..., 08..., dengan spasi/tanda hubung.
var rePhone = regexp.MustCompile(`^(\+62|62|0)[0-9]{8,13}$`)

// CreateRequest adalah payload POST /users.
type CreateRequest struct {
	NamaLengkap string `json:"nama_lengkap"`
	Email       string `json:"email"`
	NoHP        string `json:"no_hp"`
	Password    string `json:"password"`
	Role        string `json:"role"`
	Active      string `json:"active"`
	ImgProfile  string `json:"img_profile"`
}

// UpdateRequest adalah payload PUT /users/:id. Field kosong/absen tidak diubah.
type UpdateRequest struct {
	NamaLengkap *string `json:"nama_lengkap"`
	Email       *string `json:"email"`
	NoHP        *string `json:"no_hp"`
	Password    *string `json:"password"`
	Role        *string `json:"role"`
	Active      *string `json:"active"`
	ImgProfile  *string `json:"img_profile"`
}

// ChangePasswordRequest adalah payload ganti password mandiri.
type ChangePasswordRequest struct {
	OldPassword string `json:"old_password"`
	NewPassword string `json:"new_password"`
}

// Validate memeriksa CreateRequest dan mengembalikan peta field→pesan.
// CreateRequest divalidasi; aturan sama dipakai untuk update sebagian.
func (r *CreateRequest) Validate() map[string]string {
	errs := map[string]string{}

	r.NamaLengkap = strings.TrimSpace(r.NamaLengkap)
	r.Email = strings.ToLower(strings.TrimSpace(r.Email))
	r.NoHP = normalizePhone(r.NoHP)
	r.Role = strings.ToLower(strings.TrimSpace(r.Role))
	r.Active = strings.ToLower(strings.TrimSpace(r.Active))

	if r.NamaLengkap == "" {
		errs["nama_lengkap"] = "wajib diisi"
	} else if len([]rune(r.NamaLengkap)) < 3 {
		errs["nama_lengkap"] = "minimal 3 karakter"
	} else if len([]rune(r.NamaLengkap)) > 100 {
		errs["nama_lengkap"] = "maksimal 100 karakter"
	}

	if msg := validateEmail(r.Email); msg != "" {
		errs["email"] = msg
	}
	if r.NoHP != "" {
		if !rePhone.MatchString(r.NoHP) {
			errs["no_hp"] = "format nomor tidak valid (contoh 08123456789 atau +628123456789)"
		}
	}
	if r.Password != "" {
		if msg := validatePassword(r.Password); msg != "" {
			errs["password"] = msg
		}
	}
	if r.Role == "" {
		r.Role = string(RoleGuest)
	} else if r.Role != string(RoleGuest) && r.Role != string(RoleAdmin) {
		errs["role"] = "harus 'guest' atau 'admin'"
	}
	if r.Active == "" {
		r.Active = string(StatusInactive)
	} else if r.Active != string(StatusActive) && r.Active != string(StatusInactive) {
		errs["active"] = "harus 'active' atau 'inactive'"
	}
	if len(r.ImgProfile) > 255 {
		errs["img_profile"] = "maksimal 255 karakter"
	}
	return errs
}

// Validate memeriksa UpdateRequest (field opsional).
func (r *UpdateRequest) Validate() map[string]string {
	errs := map[string]string{}

	if r.NamaLengkap != nil {
		v := strings.TrimSpace(*r.NamaLengkap)
		if len([]rune(v)) < 3 {
			errs["nama_lengkap"] = "minimal 3 karakter"
		} else if len([]rune(v)) > 100 {
			errs["nama_lengkap"] = "maksimal 100 karakter"
		}
	}
	if r.Email != nil {
		v := strings.ToLower(strings.TrimSpace(*r.Email))
		if msg := validateEmail(v); msg != "" {
			errs["email"] = msg
		}
	}
	if r.NoHP != nil {
		v := normalizePhone(*r.NoHP)
		if v != "" && !rePhone.MatchString(v) {
			errs["no_hp"] = "format nomor tidak valid"
		}
	}
	if r.Password != nil && *r.Password != "" {
		if msg := validatePassword(*r.Password); msg != "" {
			errs["password"] = msg
		}
	}
	if r.Role != nil {
		v := strings.ToLower(strings.TrimSpace(*r.Role))
		if v != string(RoleGuest) && v != string(RoleAdmin) {
			errs["role"] = "harus 'guest' atau 'admin'"
		}
	}
	if r.Active != nil {
		v := strings.ToLower(strings.TrimSpace(*r.Active))
		if v != string(StatusActive) && v != string(StatusInactive) {
			errs["active"] = "harus 'active' atau 'inactive'"
		}
	}
	if r.ImgProfile != nil && len(*r.ImgProfile) > 255 {
		errs["img_profile"] = "maksimal 255 karakter"
	}
	return errs
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

func validatePassword(p string) string {
	if len(p) < 8 {
		return "minimal 8 karakter"
	}
	if len([]byte(p)) > 72 {
		return "maksimal 72 byte"
	}
	return ""
}

// normalizePhone membuang spasi, tanda hubung, dan titik.
func normalizePhone(s string) string {
	s = strings.TrimSpace(s)
	r := strings.NewReplacer(" ", "", "-", "", ".", "", "(", "", ")", "")
	return r.Replace(s)
}

// roleOrDefault mengembalikan role valid atau default guest.
func roleOrDefault(r string) Role {
	if strings.EqualFold(r, string(RoleAdmin)) {
		return RoleAdmin
	}
	return RoleGuest
}

// statusOrDefault mengembalikan status valid atau default inactive.
func statusOrDefault(s string) Status {
	if strings.EqualFold(s, string(StatusActive)) {
		return StatusActive
	}
	return StatusInactive
}

// describeErrors membuat pesan ringkas dari peta kesalahan.
func describeErrors(errs map[string]string) string {
	if len(errs) == 1 {
		for _, v := range errs {
			return v
		}
	}
	return fmt.Sprintf("%d field tidak valid", len(errs))
}
