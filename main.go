package main

import (
	"fmt"
	"log"
	"os"

	_ "github.com/joho/godotenv/autoload"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/memochou1993/password-manager-api/handler"
)

func init() {
	verifyEnv("APP_PORT")
	verifyEnv("JWT_SECRET")
}

func main() {
	app := echo.New()
	app.Use(middleware.Recover())

	api := app.Group("/api")
	api.POST("/tokens", handler.Login)

	r := api.Group("")
	r.Use(middleware.JWTWithConfig(middleware.JWTConfig{Claims: new(handler.TokenClaims), SigningKey: []byte(os.Getenv("JWT_SECRET"))}))
	r.GET("/secrets", handler.ListSecrets)
	r.POST("/secrets", handler.StoreSecret)
	r.PATCH("/secrets", handler.UpdateSecret)
	r.DELETE("/secrets", handler.DestroySecret)

	app.Logger.Fatal(app.Start(fmt.Sprintf(":%s", os.Getenv("APP_PORT"))))
}

func verifyEnv(key string) {
	if os.Getenv(key) == "" {
		log.Fatalf("env %s is required", key)
	}
}
