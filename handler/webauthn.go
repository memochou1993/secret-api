package handler

import (
	"fmt"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/golang-jwt/jwt"
	"github.com/labstack/echo/v4"
	"github.com/memochou1993/secret-api/database"
)

var (
	wa    *webauthn.WebAuthn
	waErr error
	// Store session data for registration and login
	sessionStore = make(map[string]*webauthn.SessionData)
	sessionMu    sync.RWMutex
)

func initWebAuthn() {
	if wa != nil {
		return
	}
	wa, waErr = webauthn.New(&webauthn.Config{
		RPDisplayName: "Secret API",
		RPID:          os.Getenv("WEBAUTHN_RP_ID"), // e.g., localhost or example.com
		RPOrigins:     []string{os.Getenv("WEBAUTHN_RP_ORIGIN")}, // e.g., http://localhost:3000
	})
	if waErr != nil {
		fmt.Printf("failed to create webauthn: %v\n", waErr)
	}
}

// BeginRegistration starts the registration process
func BeginRegistration(c echo.Context) error {
	initWebAuthn()
	userID := c.Get("user").(*jwt.Token).Claims.(*TokenClaims).UserID

	user := &database.User{}
	tx := database.DB().Where(&database.User{ID: userID}).First(user)
	if tx.Error != nil {
		return echo.NewHTTPError(http.StatusNotFound, "User not found")
	}

	options, sessionData, err := wa.BeginRegistration(user)
	if err != nil {
		return err
	}

	sessionMu.Lock()
	sessionStore[fmt.Sprintf("reg_%d", user.ID)] = sessionData
	sessionMu.Unlock()

	return c.JSON(http.StatusOK, options)
}

// FinishRegistration completes the registration process
func FinishRegistration(c echo.Context) error {
	initWebAuthn()
	userID := c.Get("user").(*jwt.Token).Claims.(*TokenClaims).UserID
	
	sessionMu.RLock()
	sessionData, ok := sessionStore[fmt.Sprintf("reg_%d", userID)]
	sessionMu.RUnlock()
	if !ok {
		return echo.NewHTTPError(http.StatusBadRequest, "Session not found")
	}

	user := &database.User{}
	database.DB().Where(&database.User{ID: userID}).First(user)

	credential, err := wa.FinishRegistration(user, *sessionData, c.Request())
	if err != nil {
		return err
	}

	// Store credentials
	dbCred := database.Credential{
		ID:              credential.ID,
		PublicKey:       credential.PublicKey,
		AttestationType: credential.AttestationType,
		AAGUID:          credential.Authenticator.AAGUID,
		SignCount:       credential.Authenticator.SignCount,
		CloneWarning:    credential.Authenticator.CloneWarning,
		UserID:          user.ID,
	}
	database.DB().Create(&dbCred)

	sessionMu.Lock()
	delete(sessionStore, fmt.Sprintf("reg_%d", userID))
	sessionMu.Unlock()

	return c.NoContent(http.StatusCreated)
}

type WebAuthnLoginRequest struct {
	Email string `json:"email" validate:"required"`
}

// BeginLogin starts the login process
func BeginLogin(c echo.Context) error {
	initWebAuthn()
	req := &WebAuthnLoginRequest{}
	if err := c.Bind(req); err != nil {
		return err
	}

	user := &database.User{}
	tx := database.DB().Preload("Credentials").Where(&database.User{Email: req.Email}).First(user)
	if tx.Error != nil {
		return echo.NewHTTPError(http.StatusNotFound, "User not found")
	}

	options, sessionData, err := wa.BeginLogin(user)
	if err != nil {
		return err
	}

	sessionMu.Lock()
	sessionStore[fmt.Sprintf("login_%s", req.Email)] = sessionData
	sessionMu.Unlock()

	return c.JSON(http.StatusOK, options)
}

// FinishLogin completes the login process
func FinishLogin(c echo.Context) error {
	initWebAuthn()
	req := &WebAuthnLoginRequest{}
	if err := c.Bind(req); err != nil {
		return err
	}

	sessionMu.RLock()
	sessionData, ok := sessionStore[fmt.Sprintf("login_%s", req.Email)]
	sessionMu.RUnlock()
	if !ok {
		return echo.NewHTTPError(http.StatusBadRequest, "Session not found")
	}

	user := &database.User{}
	database.DB().Preload("Credentials").Where(&database.User{Email: req.Email}).First(user)

	credential, err := wa.FinishLogin(user, *sessionData, c.Request())
	if err != nil {
		return err
	}

	database.DB().Model(&database.Credential{}).Where("id = ?", credential.ID).Update("sign_count", credential.Authenticator.SignCount)

	sessionMu.Lock()
	delete(sessionStore, fmt.Sprintf("login_%s", req.Email))
	sessionMu.Unlock()

	return issueToken(c, user)
}

// issueToken issues a JWT token
func issueToken(c echo.Context, user *database.User) error {
	// Reference handler/auth.go implementation
	// Assume JWT_TTL and JWT_SECRET are set for convenience
	ttl, _ := strconv.Atoi(os.Getenv("JWT_TTL"))
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
