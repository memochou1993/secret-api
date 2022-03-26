package handler

import (
	"errors"
	"github.com/golang-jwt/jwt"
	"github.com/labstack/echo/v4"
	"github.com/memochou1993/secret-api/database"
	"github.com/memochou1993/secret-api/util"
	"gorm.io/gorm"
	"net/http"
	"os"
	"strconv"
	"time"
)

type TokenClaims struct {
	UserID uint
	jwt.StandardClaims
}

type CreateTokenRequest struct {
	Email    string `json:"email" validate:"required"`
	Password string `json:"password" validate:"required"`
}

func CreateToken(c echo.Context) error {
	req := &CreateTokenRequest{}
	if err := c.Bind(req); err != nil {
		return err
	}
	if err := c.Validate(req); err != nil {
		return err
	}
	user := &database.User{}
	tx := database.DB().Where(&database.User{Email: req.Email}).First(user)
	if errors.Is(tx.Error, gorm.ErrRecordNotFound) {
		return echo.ErrUnauthorized
	}
	if !util.CheckPassword(req.Password, user.Password) {
		return echo.ErrUnauthorized
	}
	ttl, err := strconv.Atoi(os.Getenv("JWT_TTL"))
	if err != nil {
		return err
	}
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, &TokenClaims{
		user.ID,
		jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Second * time.Duration(ttl)).Unix(),
		},
	}).SignedString([]byte(os.Getenv("JWT_SECRET")))
	if err != nil {
		return err
	}
	return c.JSON(http.StatusOK, echo.Map{
		"token": token,
	})
}
