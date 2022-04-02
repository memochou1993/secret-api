package main

import (
	"fmt"
	"github.com/go-playground/validator"
	"github.com/memochou1993/secret-api/database"
	"log"
	"net/http"
	"os"

	_ "github.com/joho/godotenv/autoload"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/memochou1993/secret-api/handler"
)

func init() {
	verifyEnv()
	database.Migrate()
}

type CustomValidator struct {
	validator *validator.Validate
}

func (cv *CustomValidator) Validate(i interface{}) error {
	if err := cv.validator.Struct(i); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}
	return nil
}

func main() {
	app := echo.New()
	app.Use(middleware.Recover())
	app.Validator = &CustomValidator{validator: validator.New()}
	app.Use(middleware.CORSWithConfig(middleware.CORSConfig{
		AllowOrigins: []string{"*"},
		AllowHeaders: []string{"*"},
	}))

	api := app.Group("/api")
	api.POST("/tokens", handler.CreateToken)
	api.POST("/users", handler.CreateUser)

	r := api.Group("")
	r.Use(middleware.JWTWithConfig(middleware.JWTConfig{Claims: &handler.TokenClaims{}, SigningKey: []byte(os.Getenv("JWT_SECRET"))}))
	r.GET("/secrets", handler.ListSecrets)
	r.POST("/secrets", handler.CreateSecret)
	r.PATCH("/secrets/:id", handler.UpdateSecret)
	r.DELETE("/secrets/:id", handler.DestroySecret)

	app.Logger.Fatal(app.Start(fmt.Sprintf(":%s", os.Getenv("APP_PORT"))))
}

func verifyEnv() {
	keys := []string{
		"APP_PORT",
		"JWT_SECRET",
		"JWT_TTL",
	}
	for _, key := range keys {
		if os.Getenv(key) == "" {
			log.Fatalf("env %s is required", key)
		}
	}
}
