package handler

import (
	"errors"
	"github.com/labstack/echo/v4"
	"github.com/memochou1993/password-manager-api/database"
	"github.com/memochou1993/password-manager-api/util"
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
