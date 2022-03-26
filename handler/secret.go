package handler

import (
	"github.com/golang-jwt/jwt"
	"github.com/labstack/echo/v4"
	"net/http"
)

func ListSecrets(c echo.Context) error {
	// TODO
	user := c.Get("user").(*jwt.Token)
	claims := user.Claims.(*TokenClaims)
	name := claims.Name
	return c.String(http.StatusOK, name)
}

func StoreSecret(c echo.Context) error {
	// TODO
	return nil
}

func UpdateSecret(c echo.Context) error {
	// TODO
	return nil
}

func DestroySecret(c echo.Context) error {
	// TODO
	return nil
}
