package handler

import (
	"errors"
	"github.com/golang-jwt/jwt"
	"github.com/labstack/echo/v4"
	"github.com/memochou1993/secret-api/database"
	"gorm.io/gorm"
	"net/http"
	"strconv"
)

func ListSecrets(c echo.Context) error {
	userID := c.Get("user").(*jwt.Token).Claims.(*TokenClaims).UserID
	secrets := &[]database.Secret{}
	database.DB().Where(&database.Secret{UserID: userID}).Order("id DESC").Find(secrets)
	return c.JSON(http.StatusOK, echo.Map{
		"data": secrets,
	})
}

func CreateSecret(c echo.Context) error {
	userID := c.Get("user").(*jwt.Token).Claims.(*TokenClaims).UserID
	data := &database.Secret{UserID: userID}
	if err := c.Bind(data); err != nil {
		return err
	}
	if err := c.Validate(data); err != nil {
		return err
	}
	database.DB().Create(data)
	return c.JSON(http.StatusCreated, echo.Map{
		"data": data,
	})
}

func UpdateSecret(c echo.Context) error {
	userID := c.Get("user").(*jwt.Token).Claims.(*TokenClaims).UserID
	secretId, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		return err
	}
	data := &database.Secret{ID: uint(secretId), UserID: userID}
	secret := &database.Secret{}
	tx := database.DB().Where(data).First(secret)
	if errors.Is(tx.Error, gorm.ErrRecordNotFound) {
		return echo.ErrNotFound
	}
	if err := c.Bind(data); err != nil {
		return err
	}
	if err := c.Validate(data); err != nil {
		return err
	}
	database.DB().Where(secret).Updates(data)
	return c.JSON(http.StatusOK, nil)
}

func DestroySecret(c echo.Context) error {
	userID := c.Get("user").(*jwt.Token).Claims.(*TokenClaims).UserID
	secretId, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		return err
	}
	data := &database.Secret{ID: uint(secretId), UserID: userID}
	secret := &database.Secret{}
	tx := database.DB().Where(data).First(secret)
	if errors.Is(tx.Error, gorm.ErrRecordNotFound) {
		return echo.ErrNotFound
	}
	database.DB().Delete(data)
	return c.JSON(http.StatusNoContent, nil)
}
