package users

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/sekolah-alazhar/my-auth-go/utils"
)

// Controller menangani HTTP untuk modul users.
type Controller struct {
	svc *Service
}

// NewController membuat controller.
func NewController(svc *Service) *Controller { return &Controller{svc: svc} }

// List godoc
// @Summary      Daftar user
// @Description  Menampilkan semua user dengan pagination, pencarian, filter, dan sorting.
// @Tags         users
// @Produce      json
// @Security     BearerAuth
// @Param        page    query  int     false  "Halaman (default 1)"
// @Param        limit   query  int     false  "Jumlah per halaman (default 10, max 100)"
// @Param        search  query  string  false  "Cari nama_lengkap / email / no_hp"
// @Param        role    query  string  false  "Filter role (guest|admin)"
// @Param        active  query  string  false  "Filter status (active|inactive)"
// @Param        sort    query  string  false  "Kolom sort (created_at|updated_at|nama_lengkap|email|role|active)"
// @Param        order   query  string  false  "Arah sort (asc|desc)"
// @Success      200 {object} utils.Response{data=[]users.User,meta=utils.Meta}
// @Failure      401 {object} exceptions.Response
// @Failure      403 {object} exceptions.Response
// @Router       /users [get]
func (h *Controller) List(c *gin.Context) {
	p := utils.ParsePagination(c)
	sortCol, sortOrder := utils.ResolveSort(
		c.Query("sort"), c.Query("order"),
		map[string]string{
			"created_at":   "created_at",
			"updated_at":   "updated_at",
			"nama_lengkap": "nama_lengkap",
			"email":        "email",
			"role":         "role",
			"active":       "active",
		}, "created_at")

	items, total, err := h.svc.List(c.Request.Context(), ListFilter{
		Search:    c.Query("search"),
		Role:      c.Query("role"),
		Active:    c.Query("active"),
		SortCol:   sortCol,
		SortOrder: sortOrder,
		Limit:     p.Limit,
		Offset:    p.Offset,
	})
	if err != nil {
		_ = c.Error(err)
		return
	}

	utils.OKMeta(c, "Data users berhasil ditemukan", items, utils.Meta{
		Page:       p.Page,
		Limit:      p.Limit,
		Total:      total,
		TotalPages: utils.TotalPages(total, p.Limit),
	})
}

// Get godoc
// @Summary      Detail user
// @Description  Menampilkan satu user berdasarkan UUID. Password tidak pernah dikembalikan.
// @Tags         users
// @Produce      json
// @Security     BearerAuth
// @Param        id  path  string  true  "UUID user"
// @Success      200 {object} utils.Response{data=users.User}
// @Failure      404 {object} exceptions.Response
// @Router       /users/{id} [get]
func (h *Controller) Get(c *gin.Context) {
	id, ok := parseUUID(c)
	if !ok {
		return
	}

	// Guest hanya boleh melihat dirinya sendiri.
	if !isAdmin(c) && currentUserID(c) != id {
		utils.Fail(c, http.StatusForbidden, "Tidak memiliki izin", nil)
		return
	}

	u, err := h.svc.Get(c.Request.Context(), id)
	if err != nil {
		_ = c.Error(err)
		return
	}
	utils.OK(c, "Detail user", u)
}

// Create godoc
// @Summary      Tambah user
// @Description  Membuat user baru (khusus admin). User wajib mengganti password saat login pertama.
// @Tags         users
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        body  body  users.CreateRequest  true  "Data user"
// @Success      201 {object} utils.Response{data=users.User}
// @Failure      409 {object} exceptions.Response
// @Failure      422 {object} exceptions.Response
// @Router       /users [post]
func (h *Controller) Create(c *gin.Context) {
	var req CreateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.Fail(c, http.StatusBadRequest, "Body JSON tidak valid", map[string]string{
			"body": "format JSON tidak sesuai",
		})
		return
	}

	u, err := h.svc.Create(c.Request.Context(), req)
	if err != nil {
		_ = c.Error(err)
		return
	}
	utils.Created(c, "User berhasil dibuat", u)
}

// Update godoc
// @Summary      Ubah user
// @Description  Mengubah data user. Hanya field yang dikirim yang berubah. Admin tidak bisa menurunkan/menonaktifkan admin terakhir.
// @Tags         users
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        id    path  string               true  "UUID user"
// @Param        body  body  users.UpdateRequest  true  "Field yang diubah"
// @Success      200 {object} utils.Response{data=users.User}
// @Failure      404 {object} exceptions.Response
// @Failure      409 {object} exceptions.Response
// @Failure      422 {object} exceptions.Response
// @Router       /users/{id} [put]
func (h *Controller) Update(c *gin.Context) {
	id, ok := parseUUID(c)
	if !ok {
		return
	}

	// Guest hanya boleh mengubah dirinya sendiri, dan tidak boleh mengubah role/status.
	admin := isAdmin(c)
	if !admin && currentUserID(c) != id {
		utils.Fail(c, http.StatusForbidden, "Tidak memiliki izin", nil)
		return
	}

	var req UpdateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.Fail(c, http.StatusBadRequest, "Body JSON tidak valid", map[string]string{
			"body": "format JSON tidak sesuai",
		})
		return
	}

	if !admin {
		if req.Role != nil || req.Active != nil {
			utils.Fail(c, http.StatusForbidden, "Hanya admin yang boleh mengubah role/status", nil)
			return
		}
	}

	u, err := h.svc.Update(c.Request.Context(), id, req)
	if err != nil {
		_ = c.Error(err)
		return
	}
	utils.OK(c, "User berhasil diubah", u)
}

// Delete godoc
// @Summary      Hapus user
// @Description  Menghapus user (soft delete). Admin tidak bisa menghapus dirinya sendiri atau admin terakhir.
// @Tags         users
// @Produce      json
// @Security     BearerAuth
// @Param        id  path  string  true  "UUID user"
// @Success      200 {object} utils.Response
// @Failure      404 {object} exceptions.Response
// @Failure      409 {object} exceptions.Response
// @Router       /users/{id} [delete]
func (h *Controller) Delete(c *gin.Context) {
	id, ok := parseUUID(c)
	if !ok {
		return
	}
	if err := h.svc.Delete(c.Request.Context(), id, currentUserID(c)); err != nil {
		_ = c.Error(err)
		return
	}
	utils.OK(c, "User berhasil dihapus", nil)
}

// ChangePassword godoc
// @Summary      Ganti password sendiri
// @Description  Mengganti password user yang sedang login. Semua sesi lain dicabut.
// @Tags         users
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        body  body  users.ChangePasswordRequest  true  "Password lama & baru"
// @Success      200 {object} utils.Response
// @Failure      401 {object} exceptions.Response
// @Failure      422 {object} exceptions.Response
// @Router       /users/me/password [put]
func (h *Controller) ChangePassword(c *gin.Context) {
	var req ChangePasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.Fail(c, http.StatusBadRequest, "Body JSON tidak valid", nil)
		return
	}
	if err := h.svc.ChangePassword(c.Request.Context(), currentUserID(c), req.OldPassword, req.NewPassword); err != nil {
		_ = c.Error(err)
		return
	}
	utils.OK(c, "Password berhasil diganti, silakan login ulang", nil)
}

// parseUUID membaca parameter :id dan menulis 400 bila tidak valid.
func parseUUID(c *gin.Context) (uuid.UUID, bool) {
	raw := c.Param("id")
	id, err := uuid.Parse(raw)
	if err != nil {
		utils.Fail(c, http.StatusBadRequest, "UUID tidak valid", map[string]string{
			"id": "format UUID tidak sesuai",
		})
		return uuid.Nil, false
	}
	return id, true
}

// currentUserID mengambil UUID user dari context (diisi middleware auth).
func currentUserID(c *gin.Context) uuid.UUID {
	v, ok := c.Get("user_id")
	if !ok {
		return uuid.Nil
	}
	switch t := v.(type) {
	case uuid.UUID:
		return t
	case string:
		id, err := uuid.Parse(t)
		if err != nil {
			return uuid.Nil
		}
		return id
	}
	return uuid.Nil
}

// isAdmin memeriksa role di context.
func isAdmin(c *gin.Context) bool {
	v, ok := c.Get("role")
	if !ok {
		return false
	}
	s, _ := v.(string)
	return s == string(RoleAdmin)
}
