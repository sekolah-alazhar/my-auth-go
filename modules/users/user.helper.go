package users

import (
	"errors"
	"strings"

	"github.com/go-sql-driver/mysql"
	"gorm.io/gorm"
)

// gormExprIncrement menghasilkan ekspresi SQL untuk menaikkan token_version.
func gormExprIncrement() any {
	return gorm.Expr("token_version + 1")
}

// isDuplicate mendeteksi pelanggaran unique constraint (MySQL error 1062).
func isDuplicate(err error) bool {
	var me *mysql.MySQLError
	if errors.As(err, &me) {
		return me.Number == 1062
	}
	// fallback bila driver membungkus pesan
	return strings.Contains(strings.ToLower(err.Error()), "duplicate entry")
}
