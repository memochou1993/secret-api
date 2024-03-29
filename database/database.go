package database

import (
	"fmt"
	"log"
	"os"
	"time"

	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

var (
	db  *gorm.DB
	err error
)

type BaseModel struct {
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type User struct {
	ID       uint   `json:"id" gorm:"primarykey"`
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required,min=8"`
	BaseModel
}

type Secret struct {
	ID         uint   `json:"id" gorm:"primarykey"`
	Name       string `json:"name" validate:"required"`
	Ciphertext string `json:"ciphertext" validate:"required"`
	UserID     uint   `json:"-"`
	BaseModel
}

func Init() {
	dsn := fmt.Sprintf(
		"%s:%s@tcp(%s:%s)/%s?charset=utf8mb4&parseTime=true",
		os.Getenv("DB_USERNAME"),
		os.Getenv("DB_PASSWORD"),
		os.Getenv("DB_HOST"),
		os.Getenv("DB_PORT"),
		os.Getenv("DB_DATABASE"),
	)
	db, err = gorm.Open(mysql.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatalln(err)
	}
}

func DB() *gorm.DB {
	return db
}

func Migrate() {
	if err := db.AutoMigrate(
		&User{},
		&Secret{},
	); err != nil {
		log.Fatalln(err)
	}
}
