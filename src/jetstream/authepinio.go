package main

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"math"
	"net/http"
	"net/url"

	log "github.com/sirupsen/logrus"

	"github.com/labstack/echo/v4"

	eInterfaces "github.com/epinio/ui-backend/src/jetstream/plugins/epinio/interfaces"
	"github.com/epinio/ui-backend/src/jetstream/plugins/epinio/rancherproxy"

	"github.com/epinio/ui-backend/src/jetstream/repository/interfaces"
)

//More fields will be moved into here as global portalProxy struct is phased out
type epinioAuth struct {
	databaseConnectionPool *sql.DB
	p                      *portalProxy
}

func (a *epinioAuth) ShowConfig(config *interfaces.ConsoleConfig) {
	log.Infof("... Epinio Auth             : %v", true)
}

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

	// Perform the login and fetch session values if successful
	userGUID, username, err := a.epinioLogin(c)

	if err != nil {
		//Login failed, return response.
		resp := &rancherproxy.LoginErrorRes{
			Type:      "error",
			BasetType: "error",
			Code:      "Unauthorized",
			Status:    http.StatusUnauthorized,
			Message:   err.Error(),
		}

		if jsonString, err := json.Marshal(resp); err == nil {
			c.Response().Status = http.StatusUnauthorized
			c.Response().Header().Set("Content-Type", "application/json")
			c.Response().Write(jsonString)
		}

		return nil
	}

	err = a.generateLoginSuccessResponse(c, userGUID, username)

	return err
}

//Logout provides Local-auth specific Stratos login
func (a *epinioAuth) Logout(c echo.Context) error {
	log.Debug("Logout")
	return a.logout(c)
}

//GetUsername gets the user name for the specified local user
func (a *epinioAuth) GetUsername(userid string) (string, error) {
	log.Debug("GetUsername")

	return userid, nil // username == user guid
}

//GetUser gets the user guid for the specified local user
func (a *epinioAuth) GetUser(userGUID string) (*interfaces.ConnectedUser, error) {
	log.Debug("GetUser")

	var scopes []string
	scopes = make([]string, 0) // User has no stratos scopes such as "stratos.admin", "password.write", "scim.write"

	connectedUser := &interfaces.ConnectedUser{
		GUID:   userGUID,
		Name:   userGUID,
		Admin:  false,
		Scopes: scopes,
	}

	return connectedUser, nil
}

func (a *epinioAuth) BeforeVerifySession(c echo.Context) {}

func (a *epinioAuth) VerifySession(c echo.Context, sessionUser string, sessionExpireTime int64) error {
	// Never expires
	// Only really used by `/v1/auth/verify`
	return nil
}

//epinioLogin verifies local user credentials against our DB
func (a *epinioAuth) epinioLogin(c echo.Context) (string, string, error) {
	log.Debug("doLocalLogin")

	username, password, err := a.getRancherUsernameAndPassword(c)
	if err != nil {
		return "", "", err
	}

	if err := a.verifyEpinioCreds(username, password); err != nil {
		return "", "", err
	}

	// User guid, user name, err
	return username, username, nil
}

func (a *epinioAuth) getRancherUsernameAndPassword(c echo.Context) (string, string, error) {
	defer c.Request().Body.Close()
	body, err := ioutil.ReadAll(c.Request().Body)
	if err != nil {
		return "", "", err
	}

	var params rancherproxy.LoginParams
	if err = json.Unmarshal(body, &params); err != nil {
		return "", "", err
	}

	username := params.Username
	password := params.Password

	if len(username) == 0 || len(password) == 0 {
		return "", username, errors.New("Username and/or password required")
	}

	// Set these so they're available in the epinio plugin login
	c.Set("rancher_username", username)
	c.Set("rancher_password", password)

	return username, password, nil
}

func (a *epinioAuth) verifyEpinioCreds(username, password string) error {
	log.Debug("verifyEpinioCreds")

	// Find the epinio endpoint
	endpoints, err := a.p.ListEndpoints()
	if err != nil {
		msg := "Failed to fetch list of endpoints: %+v"
		log.Errorf(msg, err)
		return fmt.Errorf(msg, err)
	}

	var epinioEndpoint *interfaces.CNSIRecord
	for _, e := range endpoints {
		if e.CNSIType == eInterfaces.EndpointType {
			epinioEndpoint = e
			break
		}
	}

	if epinioEndpoint == nil {
		msg := "Failed to find an epinio endpoint"
		log.Error(msg)
		return fmt.Errorf(msg)
	}

	// Make a request to the epinio endpoint that requires auth
	credsUrl := fmt.Sprintf("%s/api/v1/info", epinioEndpoint.APIEndpoint.String())

	req, err := http.NewRequest("GET", credsUrl, nil)
	if err != nil {
		msg := "Failed to create request to verify epinio creds: %v"
		log.Errorf(msg, err)
		return fmt.Errorf(msg, err)
	}

	req.SetBasicAuth(url.QueryEscape(username), url.QueryEscape(password))

	var h = a.p.GetHttpClientForRequest(req, epinioEndpoint.SkipSSLValidation)
	res, err := h.Do(req)
	if err != nil || res.StatusCode != http.StatusOK {
		log.Errorf("Error performing verify epinio creds - response: %v, error: %v", res, err)
		return interfaces.LogHTTPError(res, err)
	}

	defer res.Body.Close()

	return nil

}

//generateLoginSuccessResponse
func (e *epinioAuth) generateLoginSuccessResponse(c echo.Context, userGUID, username string) error {
	log.Debug("generateLoginSuccessResponse")

	var err error
	var expiry int64
	expiry = math.MaxInt64 // Basic auth type never expires

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

	err = e.p.ExecuteLoginHooks(c)
	if err != nil {
		log.Warnf("Login hooks failed: %v", err)
	}

	resp := &interfaces.LoginRes{
		Account:     username,
		TokenExpiry: expiry,
		APIEndpoint: nil,
		Admin:       false,
	}

	if jsonString, err := json.Marshal(resp); err == nil {
		// Add XSRF Token
		e.p.ensureXSRFToken(c)

		// Swap Stratos's cross-site request forgery token for Rancher
		cookie := new(http.Cookie)
		cookie.Name = "CSRF" // This matches Rancher's cookie name for the token
		cookie.Value = c.Response().Header().Get(interfaces.XSRFTokenHeader)
		cookie.Domain = e.p.SessionStoreOptions.Domain
		cookie.Secure = e.p.SessionStoreOptions.Secure
		cookie.Path = e.p.SessionStoreOptions.Path
		cookie.MaxAge = 0
		c.SetCookie(cookie)

		c.Response().Header().Set("Content-Type", "application/json")
		c.Response().Write(jsonString)
	}

	return err
}

//logout
func (a *epinioAuth) logout(c echo.Context) error {
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
