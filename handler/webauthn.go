package handler

import (
	"fmt"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/golang-jwt/jwt"
	"github.com/labstack/echo/v4"
	"github.com/memochou1993/secret-api/database"
)

var (
	wa    *webauthn.WebAuthn
	waErr error
	// Store session data for registration and login.
	// Registration sessions are keyed by user ID (the user is known via JWT).
	// Login sessions are keyed by challenge because in discoverable flow the
	// user is unknown until the assertion is received.
	sessionStore = make(map[string]*webauthn.SessionData)
	sessionMu    sync.RWMutex
)

func initWebAuthn() {
	if wa != nil {
		return
	}
	wa, waErr = webauthn.New(&webauthn.Config{
		RPDisplayName: "Secret API",
		RPID:          os.Getenv("WEBAUTHN_RP_ID"),
		RPOrigins:     []string{os.Getenv("WEBAUTHN_RP_ORIGIN")},
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

	return c.JSON(http.StatusOK, options.Response)
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

	dbCred := database.Credential{
		ID:              credential.ID,
		PublicKey:       credential.PublicKey,
		AttestationType: credential.AttestationType,
		AAGUID:          credential.Authenticator.AAGUID,
		SignCount:       credential.Authenticator.SignCount,
		CloneWarning:    credential.Authenticator.CloneWarning,
		Flags:           uint8(credential.Flags.ProtocolValue()),
		UserID:          user.ID,
	}
	database.DB().Create(&dbCred)

	sessionMu.Lock()
	delete(sessionStore, fmt.Sprintf("reg_%d", userID))
	sessionMu.Unlock()

	return c.NoContent(http.StatusCreated)
}

// BeginLogin starts a discoverable (passkey) login. No user identity is required;
// the authenticator response will reveal which user is signing in.
func BeginLogin(c echo.Context) error {
	initWebAuthn()

	options, sessionData, err := wa.BeginDiscoverableLogin()
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	sessionMu.Lock()
	sessionStore["login_"+sessionData.Challenge] = sessionData
	sessionMu.Unlock()

	return c.JSON(http.StatusOK, options.Response)
}

// FinishLogin completes a discoverable (passkey) login.
func FinishLogin(c echo.Context) error {
	initWebAuthn()

	parsedResponse, err := protocol.ParseCredentialRequestResponse(c.Request())
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}

	challenge := parsedResponse.Response.CollectedClientData.Challenge

	sessionMu.RLock()
	sessionData, ok := sessionStore["login_"+challenge]
	sessionMu.RUnlock()
	if !ok {
		return echo.NewHTTPError(http.StatusBadRequest, "Session not found")
	}

	handler := func(rawID, userHandle []byte) (webauthn.User, error) {
		userID, err := strconv.ParseUint(string(userHandle), 10, 64)
		if err != nil {
			return nil, err
		}
		user := &database.User{}
		tx := database.DB().Preload("Credentials").Where(&database.User{ID: uint(userID)}).First(user)
		if tx.Error != nil {
			return nil, tx.Error
		}
		return *user, nil
	}

	user, credential, err := wa.ValidatePasskeyLogin(handler, *sessionData, parsedResponse)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}

	dbUser, ok := user.(database.User)
	if !ok {
		return echo.NewHTTPError(http.StatusInternalServerError, "user type assertion failed")
	}

	database.DB().Model(&database.Credential{}).Where("id = ?", credential.ID).Update("sign_count", credential.Authenticator.SignCount)

	sessionMu.Lock()
	delete(sessionStore, "login_"+challenge)
	sessionMu.Unlock()

	return issueToken(c, &dbUser)
}

// issueToken issues a JWT token
func issueToken(c echo.Context, user *database.User) error {
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
		"email": user.Email,
	})
}
