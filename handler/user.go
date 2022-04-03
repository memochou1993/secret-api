package handler

import (
	"errors"
	"github.com/golang-jwt/jwt"
	"github.com/labstack/echo/v4"
	"github.com/memochou1993/secret-api/database"
	"github.com/memochou1993/secret-api/util"
	"gorm.io/gorm"
	"net/http"
)

func CreateUser(c echo.Context) error {
	data := &database.User{}
	if err := c.Bind(data); err != nil {
		return err
	}
	if err := c.Validate(data); err != nil {
		return err
	}
	tx := database.DB().Where(&database.User{Email: data.Email}).First(&database.User{})
	if !errors.Is(tx.Error, gorm.ErrRecordNotFound) {
		return c.JSON(http.StatusBadRequest, echo.Map{
			"message": "The email has already been taken",
		})
	}
	hash, err := util.HashPassword(data.Password)
	if err != nil {
		return err
	}
	data.Password = hash
	database.DB().Create(data)
	return c.JSON(http.StatusCreated, nil)
}

func UpdateUser(c echo.Context) error {
	userID := c.Get("user").(*jwt.Token).Claims.(*TokenClaims).UserID
	data := &database.User{}
	if err := c.Bind(data); err != nil {
		return err
	}
	if err := c.Validate(data); err != nil {
		return err
	}
	user := &database.User{}
	tx := database.DB().Where(&database.User{Email: data.Email}).First(user)
	if !errors.Is(tx.Error, gorm.ErrRecordNotFound) && user.ID != userID {
		return c.JSON(http.StatusBadRequest, echo.Map{
			"message": "The email has already been taken",
		})
	}
	if data.Password != "" {
		hash, err := util.HashPassword(data.Password)
		if err != nil {
			return err
		}
		data.Password = hash
	}
	database.DB().Where(&database.User{ID: userID}).Updates(data)
	return c.JSON(http.StatusOK, nil)
}
