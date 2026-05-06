package database

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
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
	ID          uint         `json:"id" gorm:"primarykey"`
	Email       string       `json:"email" validate:"required,email"`
	Password    string       `json:"password" validate:"required,min=8"`
	Credentials []Credential `json:"-"`
	BaseModel
}

func (u User) WebAuthnID() []byte {
	return []byte(fmt.Sprintf("%d", u.ID))
}

func (u User) WebAuthnName() string {
	return u.Email
}

func (u User) WebAuthnDisplayName() string {
	return u.Email
}

func (u User) WebAuthnIcon() string {
	return ""
}

func (u User) WebAuthnCredentials() []webauthn.Credential {
	res := []webauthn.Credential{}
	for _, cred := range u.Credentials {
		res = append(res, webauthn.Credential{
			ID:              cred.ID,
			PublicKey:       cred.PublicKey,
			AttestationType: cred.AttestationType,
			Transport:       nil,
			Authenticator: webauthn.Authenticator{
				AAGUID:       cred.AAGUID,
				SignCount:    cred.SignCount,
				CloneWarning: cred.CloneWarning,
			},
		})
	}
	return res
}

type Credential struct {
	ID              []byte `gorm:"primarykey;type:varbinary(1023)"`
	PublicKey       []byte
	AttestationType string
	AAGUID          []byte
	SignCount       uint32
	CloneWarning    bool
	UserID          uint
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
		&Credential{},
	); err != nil {
		log.Fatalln(err)
	}
}
