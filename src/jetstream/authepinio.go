package main

import (
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"math"
	"net/http"
	// "strings"
	// "time"

	log "github.com/sirupsen/logrus"

	"github.com/labstack/echo/v4"

	// "github.com/epinio/ui-backend/src/jetstream/crypto"
	"github.com/epinio/ui-backend/src/jetstream/plugins/epinio/rancherproxy"
	"github.com/epinio/ui-backend/src/jetstream/repository/interfaces"
	// "github.com/epinio/ui-backend/src/jetstream/repository/localusers"
)

//More fields will be moved into here as global portalProxy struct is phased out
type epinioAuth struct {
	databaseConnectionPool *sql.DB
	// localUserScope         string
	// consoleAdminScope      string
	p                      *portalProxy
}

func (a *epinioAuth) ShowConfig(config *interfaces.ConsoleConfig) {
	log.Infof("... Epinio Auth              : %s", true) // TODO: RC
	// log.Infof("... Local User Scope        : %s", config.LocalUserScope)
}

const (
	tempUserName = "WOOPWOOP"
	tempUserGuid = "1234"
)

//Login provides Local-auth specific Stratos login
func (a *epinioAuth) Login(c echo.Context) error {

	//This check will remain in until auth is factored down into its own package
	if interfaces.AuthEndpointTypes[a.p.Config.ConsoleConfig.AuthEndpointType] != interfaces.Epinio {
		err := interfaces.NewHTTPShadowError(
			http.StatusNotFound,
			"Epinio Login is not enabled",
			"Epinio Login is not enabled")
		return err
	}


	// authString := fmt.Sprintf("%s:%s", auth.Username, auth.Password)
	// base64EncodedAuthString := base64.StdEncoding.EncodeToString([]byte(authString))
    // Perform the login and fetch session values if successful
	userGUID, username, tr, err := a.localLogin(c)
	// userGUID := tempUserGuid
	// username := tempUserName

	if err != nil {
		//Login failed, return response.
		resp := &rancherproxy.LoginErrorRes{
			Type:      "error",
			BasetType: "error",
			Code:      "Unauthorized",
			Status:    401,// TODO: RC
			Message:   err.Error(),
		}

		if jsonString, err := json.Marshal(resp); err == nil {
			c.Response().Status = 401// TODO: RC
			c.Response().Header().Set("Content-Type", "application/json")
			c.Response().Write(jsonString)
		}

		return nil
	}

	err = a.generateLoginSuccessResponse(c, userGUID, tr, username)

	return err
}

//Logout provides Local-auth specific Stratos login
func (a *epinioAuth) Logout(c echo.Context) error {
	return a.logout(c)
}

//GetUsername gets the user name for the specified local user
func (a *epinioAuth) GetUsername(userid string) (string, error) {
	log.Debug("GetUsername")

	return tempUserName, nil; // TODO: RC

	// localUsersRepo, err := localusers.NewPgsqlLocalUsersRepository(a.databaseConnectionPool)
	// if err != nil {
	// 	log.Errorf("Database error getting repo for Local users: %v", err)
	// 	return "", err
	// }

	// localUser, err := localUsersRepo.FindUser(userid)
	// if err != nil {
	// 	log.Errorf("Error fetching username for local user %s: %v", userid, err)
	// 	return "", err
	// }

	// return localUser.Username, nil
}

//GetUser gets the user guid for the specified local user
func (a *epinioAuth) GetUser(userGUID string) (*interfaces.ConnectedUser, error) {
	log.Debug("GetUser")

	// localUsersRepo, err := localusers.NewPgsqlLocalUsersRepository(a.databaseConnectionPool)
	// if err != nil {
	// 	log.Errorf("Database error getting repo for Local users: %v", err)
	// 	return nil, err
	// }

	// user, err := localUsersRepo.FindUser(userGUID)
	// if err != nil {
	// 	return nil, err
	// }

	// uaaAdmin := (user.Scope == a.p.Config.ConsoleConfig.ConsoleAdminScope)
	uaaAdmin := false

	var scopes []string
	scopes = make([]string, 3)
	scopes[0] = "stratos.admin" // user.Scope // TODO: RC
	scopes[1] = "password.write"
	scopes[2] = "scim.write"

	connectedUser := &interfaces.ConnectedUser{
		GUID:   tempUserGuid,
		Name:   tempUserName,
		Admin:  uaaAdmin,
		Scopes: scopes,
	}

	return connectedUser, nil
}

func (a *epinioAuth) BeforeVerifySession(c echo.Context) {}

//VerifySession verifies the session the specified local user, currently just verifies user exists
func (a *epinioAuth) VerifySession(c echo.Context, sessionUser string, sessionExpireTime int64) error {
	return nil // TODO: RC
	// localUsersRepo, err := localusers.NewPgsqlLocalUsersRepository(a.databaseConnectionPool)
	// if err != nil {
	// 	log.Errorf("Database error getting repo for Local users: %v", err)
	// 	return err
	// }

	// _, err = localUsersRepo.FindPasswordHash(sessionUser)
	// return err
}

//localLogin verifies local user credentials against our DB
func (a *epinioAuth) localLogin(c echo.Context) (string, string, *interfaces.TokenRecord, error) {
	log.Debug("doLocalLogin")

	defer c.Request().Body.Close()
	body, err := ioutil.ReadAll(c.Request().Body)
	if err != nil {
		return "", "", nil, err
	}

	var params rancherproxy.LoginParams
	if err = json.Unmarshal(body, &params); err != nil {
		return "", "", nil, err
	}

	username := params.Username
	password := params.Password

	if len(username) == 0 || len(password) == 0 {
		return "", username, nil, errors.New("Username and/or password required")
	}

	authString := fmt.Sprintf("%s:%s", username, password)
	base64EncodedAuthString := base64.StdEncoding.EncodeToString([]byte(authString))

	// TODO: RC Wire in to check epinio creds check, for now just accept them



	tr := &interfaces.TokenRecord{
		AuthType:     interfaces.AuthTypeHttpBasic,
		AuthToken:    base64EncodedAuthString,
		RefreshToken: username,
	}

	return username, username, tr, nil

}

func (e *epinioAuth) saveAuthToken(key string, t interfaces.TokenRecord) error {
	log.Debug("saveAuthToken")

	tokenRepo, err := e.p.GetStoreFactory().TokenStore()
	if err != nil {
		return fmt.Errorf("Database error getting repo for Epinio token: %v", err)
	}

	err = tokenRepo.SaveAuthToken(key, t, e.p.Config.EncryptionKeyInBytes)
	if err != nil {
		return fmt.Errorf("Database error saving Epinio token: %v", err)
	}

	return nil
}

//generateLoginSuccessResponse
func (e *epinioAuth) generateLoginSuccessResponse(c echo.Context, userGUID string, token *interfaces.TokenRecord, username string) error {
	log.Debug("generateLoginSuccessResponse")

	var err error
	var expiry int64
	expiry = math.MaxInt64

	sessionValues := make(map[string]interface{})
	sessionValues["user_id"] = userGUID
	sessionValues["exp"] = expiry

	// Ensure that login disregards cookies from the request
	req := c.Request()
	req.Header.Set("Cookie", "")
	if err = e.p.setSessionValues(c, sessionValues); err != nil {
		return err
	}

	//Makes sure the client gets the right session expiry time
	if err = e.p.handleSessionExpiryHeader(c); err != nil {
		return err
	}

	err = e.saveAuthToken(userGUID, &token)
	if err != nil {
		return err
	}

	err = e.p.ExecuteLoginHooks(c)
	if err != nil {
		log.Warnf("Login hooks failed: %v", err)
	}

	resp := &interfaces.LoginRes{
		Account:     username,
		TokenExpiry: expiry,
		APIEndpoint: nil,
		Admin:       true,
	}

	if jsonString, err := json.Marshal(resp); err == nil {
		// Add XSRF Token
		e.p.ensureXSRFToken(c)
		c.Response().Header().Set("Content-Type", "application/json")
		c.Response().Write(jsonString)
	}

	return err
}

//logout
func (a *epinioAuth) logout(c echo.Context) error {
	// TODO: RC
	log.Debug("logout")

	a.p.removeEmptyCookie(c)

	// Remove the XSRF Token from the session
	a.p.unsetSessionValue(c, XSRFTokenSessionName)

	err := a.p.clearSession(c)
	if err != nil {
		log.Errorf("Unable to clear session: %v", err)
	}

	// Send JSON document
	resp := &LogoutResponse{
		IsSSO: a.p.Config.SSOLogin,
	}

	return c.JSON(http.StatusOK, resp)
}
