package users

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/sekolah-alazhar/my-auth-go/utils"
)

// Me godoc
// @Summary      Profil sendiri
// @Description  Menampilkan data user yang sedang login.
// @Tags         users
// @Produce      json
// @Security     BearerAuth
// @Success      200 {object} utils.Response{data=users.User}
// @Failure      401 {object} exceptions.Response
// @Router       /users/me [get]
func (h *Controller) Me(c *gin.Context) {
	u, err := h.svc.Get(c.Request.Context(), currentUserID(c))
	if err != nil {
		_ = c.Error(err)
		return
	}
	utils.OK(c, "Profil user", u)
}

var _ = http.StatusOK
