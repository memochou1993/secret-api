package handler

import (
	"github.com/golang-jwt/jwt"
	"github.com/labstack/echo/v4"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"
)

type TokenClaims struct {
	Name string `json:"name"`
	jwt.StandardClaims
}

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func Login(c echo.Context) error {
	u := new(LoginRequest)
	if err := c.Bind(u); err != nil {
		log.Fatalln(err)
	}
	// FIXME
	if u.Username != "" || u.Password != "" {
		return echo.ErrUnauthorized
	}
	ttl, _ := strconv.Atoi(os.Getenv("JWT_TTL"))
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, &TokenClaims{
		u.Username,
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
