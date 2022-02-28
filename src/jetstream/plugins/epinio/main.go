package epinio

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strconv"

	eInterfaces "github.com/epinio/ui-backend/src/jetstream/plugins/epinio/interfaces"
	normanProxy "github.com/epinio/ui-backend/src/jetstream/plugins/epinio/rancherproxy/norman"
	steveProxy "github.com/epinio/ui-backend/src/jetstream/plugins/epinio/rancherproxy/steve"

	"github.com/epinio/ui-backend/src/jetstream/repository/interfaces"

	"github.com/labstack/echo/v4"
	log "github.com/sirupsen/logrus"
)

const (
	epinioApiUrlEnv                  = "EPINIO_API_URL"
	epinioApiWsUrl                   = "EPINIO_API_WS_URL"
	epinioApiUrlskipSSLValidationEnv = "EPINIO_API_SKIP_SSL"
)

// Epinio - Plugin
type Epinio struct {
	portalProxy                   interfaces.PortalProxy
	epinioApiUrl                  string
	epinioApiWsUrl                string
	epinioApiUrlskipSSLValidation bool
}

func init() {
	interfaces.AddPlugin(eInterfaces.EndpointType, nil, Init)
}

// Init creates a new Analysis
func Init(portalProxy interfaces.PortalProxy) (interfaces.StratosPlugin, error) {
	if interfaces.AuthEndpointTypes[portalProxy.GetConfig().AuthEndpointType] != interfaces.Epinio {
		return nil, fmt.Errorf("Epinio plugin requires auth endpoint type of %s", interfaces.Epinio)
	}

	epinioApiUrlValue := os.Getenv(epinioApiUrlEnv)
	if len(epinioApiUrlValue) == 0 {
		return nil, fmt.Errorf("Failed to find Epinio API url env `%s`", epinioApiUrlEnv)
	}

	epinioApiWsUrlValue := os.Getenv(epinioApiWsUrl)
	if len(epinioApiWsUrlValue) == 0 {
		log.Warnf("Failed to find Epinio WS API url env `%s`", epinioApiWsUrl)
	}

	epinioApiUrlskipSSLValidation, err := strconv.ParseBool(os.Getenv(epinioApiUrlskipSSLValidationEnv))
	if err != nil {
		epinioApiUrlskipSSLValidation = false
	}

	log.Infof("Epinio API url: %s. Skipping SSL Validation: %+v", epinioApiUrlValue, epinioApiUrlskipSSLValidation)

	return &Epinio{
		portalProxy:                   portalProxy,
		epinioApiUrl:                  epinioApiUrlValue,
		epinioApiWsUrl:                epinioApiWsUrlValue,
		epinioApiUrlskipSSLValidation: epinioApiUrlskipSSLValidation,
	}, nil
}

// MiddlewarePlugin interface
func (epinio *Epinio) EchoMiddleware(h echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		return h(c)
	}
}

// MiddlewarePlugin interface
func (epinio *Epinio) SessionEchoMiddleware(h echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		req := c.Request()
		if req.Header.Get("x-api-csrf") != "" {
			// Swap Rancher's cross-site request forgery token for Stratos's
			log.Debugf("Swapping %+v for %+v", req.Header.Get("x-api-csrf"), interfaces.XSRFTokenHeader)
			req.Header.Set(interfaces.XSRFTokenHeader, req.Header.Get("x-api-csrf"))
		}
		return h(c)
	}
}

// GetMiddlewarePlugin gets the middleware plugin for this plugin
func (epinio *Epinio) GetMiddlewarePlugin() (interfaces.MiddlewarePlugin, error) {
	return epinio, nil
}

// GetEndpointPlugin gets the endpoint plugin for this plugin
func (epinio *Epinio) GetEndpointPlugin() (interfaces.EndpointPlugin, error) {
	return epinio, nil
}

func (epinio *Epinio) GetType() string {
	return eInterfaces.EndpointType
}

func (epinio *Epinio) Register(echoContext echo.Context) error {
	log.Debug("Epinio Register...")
	return epinio.portalProxy.RegisterEndpoint(echoContext, epinio.Info)
}

func (epinio *Epinio) Validate(userGUID string, cnsiRecord interfaces.CNSIRecord, tokenRecord interfaces.TokenRecord) error {
	// Validate is used to confirm the user's creds after the user connects
	// For this flow we don't need to do this, it was done when the user logs in in authepinio
	// (makes a request to `/api/v1/info`)
	return nil
}

// GetRoutePlugin gets the route plugin for this plugin
func (epinio *Epinio) GetRoutePlugin() (interfaces.RoutePlugin, error) {
	return epinio, nil
}

// AddAdminGroupRoutes adds the admin routes for this plugin to the Echo server
func (epinio *Epinio) AddAdminGroupRoutes(echoGroup *echo.Group) {
	// no-op
}

// AddSessionGroupRoutes adds the session routes for this plugin to the Echo server
func (epinio *Epinio) AddSessionGroupRoutes(echoGroup *echo.Group) {
	// no-op
}

func (epinio *Epinio) AddRootGroupRoutes(echoGroup *echo.Group) {

	p := epinio.portalProxy

	epinioGroup := echoGroup.Group("/epinio")

	rancherProxyGroup := epinioGroup.Group("/rancher")

	// Rancher Steve API
	steveGroup := rancherProxyGroup.Group("/v1")
	steveGroup.Use(p.SetSecureCacheContentMiddleware)
	steveGroup.Use(func(h echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			// TODO: RC Tech Debt - This was done as there was no pp/session access in the rancher proxy stuff. Can now be fixed
			userID, err := p.GetSessionValue(c, "user_id")
			if err == nil {
				c.Set("user_id", userID)
			}
			return h(c)
		}
	})

	// Rancher Steve API (unsecure)
	steveGroup.GET("/management.cattle.io.setting", steveProxy.MgmtSettings)

	// Rancher Steve API (secure)
	steveGroup.Use(p.SessionMiddleware())
	steveGroup.GET("/management.cattle.io.cluster", steveProxy.Clusters)
	steveGroup.GET("/schemas", steveProxy.SteveSchemas)
	steveGroup.GET("/userpreferences", steveProxy.GetUserPrefs)
	steveGroup.PUT("/userpreferences/*", steveProxy.GetSpecificUserPrefs)

	// Rancher Norman API
	normanGroup := rancherProxyGroup.Group("/v3")
	normanGroup.Use(p.SetSecureCacheContentMiddleware)
	// Rancher Norman API (secure)
	normanGroup.Use(p.SessionMiddleware())
	normanGroup.GET("/users", normanProxy.GetUser)
	normanGroup.POST("/tokens", func(c echo.Context) error {
		return normanProxy.TokenLogout(c, p)
	})
	normanGroup.GET("/principals", normanProxy.GetPrincipals)
	normanGroup.GET("/schemas", normanProxy.NormanSchemas)

	// Rancher Norman API (public)
	normanPublicGroup := rancherProxyGroup.Group("/v3-public")
	normanPublicGroup.Use(p.SetSecureCacheContentMiddleware)
	normanPublicGroup.POST("/authProviders/local/login", p.GetStratosAuthService().Login)
	normanPublicGroup.GET("/authProviders", normanProxy.GetAuthProviders)

}

func (epinio *Epinio) findEpinioEndpoint() (*interfaces.CNSIRecord, error) {
	endpoints, err := epinio.portalProxy.ListEndpoints()
	if err != nil {
		msg := "failed to fetch list of endpoints: %+v"
		log.Errorf(msg, err)
		return nil, fmt.Errorf(msg, err)
	}

	var epinioEndpoint *interfaces.CNSIRecord
	for _, e := range endpoints {
		if e.CNSIType == eInterfaces.EndpointType {
			epinioEndpoint = e
			break
		}
	}

	if epinioEndpoint == nil {
		msg := "failed to find an epinio endpoint"
		log.Error(msg)
		return nil, fmt.Errorf(msg)
	}

	return epinioEndpoint, nil
}

// Init performs plugin initialization
func (epinio *Epinio) Init() error {
	// Add login hook to automatically register and connect to the Cloud Foundry when the user logs in
	epinio.portalProxy.AddLoginHook(0, epinio.loginHook)

	cnsiName := "default" // This must match EPINIO_STANDALONE_CLUSTER_ID in front end
	apiEndpoint := epinio.epinioApiUrl
	apiWsUrl := epinio.epinioApiWsUrl
	skipSSLValidation := epinio.epinioApiUrlskipSSLValidation
	fetchInfo := epinio.Info

	if epinioCnsi, err := epinio.findEpinioEndpoint(); err == nil {

		if epinioCnsi.APIEndpoint.String() == apiEndpoint && epinioCnsi.DopplerLoggingEndpoint == apiWsUrl {
			// skip
			log.Infof("Found existing endpoint %s as \"%s\" (%s) with the same API & WS API. Skipping auto-registration", apiEndpoint, cnsiName, epinioCnsi.GUID)
			return nil
		}

		log.Infof("Found existing endpoint %s as \"%s\" (%s). Removing in case of updates", apiEndpoint, cnsiName, epinioCnsi.GUID)

		cnsiRepo, err := epinio.portalProxy.GetStoreFactory().EndpointStore()
		if err != nil {
			msg := "Unable to establish a cnsi database reference: '%v'"
			log.Errorf(msg, err)
			return fmt.Errorf(msg, err)
		}

		// Delete the endpoint
		err = cnsiRepo.Delete(epinioCnsi.GUID)
		if err != nil {
			msg := "Unable to delete existing epinio record: %v"
			log.Errorf(msg, err)
			return fmt.Errorf(msg, err)
		}

		tokenRepo, err := epinio.portalProxy.GetStoreFactory().TokenStore()
		if err != nil {
			msg := "Unable to establish a token database reference: '%v'"
			log.Errorf(msg, err)
			return fmt.Errorf(msg, err)
		}

		err = tokenRepo.DeleteCNSITokens(epinioCnsi.GUID)
		if err != nil {
			msg := "Unable to delete epinio Tokens: %v"
			log.Errorf(msg, err)
			return fmt.Errorf(msg, err)
		}
	}

	epinioCnsi, err := epinio.portalProxy.DoRegisterEndpoint(cnsiName, apiEndpoint, skipSSLValidation, "", "", false, "", fetchInfo)
	log.Infof("Auto-registering epinio endpoint %s as \"%s\" (%s)", apiEndpoint, cnsiName, epinioCnsi.GUID)

	if err != nil {
		log.Errorf("Could not auto-register Epinio endpoint: %v. %+v", err, epinioCnsi)
		return nil
	}

	return nil
}

func (epinio *Epinio) Info(apiEndpoint string, skipSSLValidation bool) (interfaces.CNSIRecord, interface{}, error) {
	log.Debug("Info")
	v2InfoResponse := interfaces.V2Info{}

	newCNSI := interfaces.CNSIRecord{
		CNSIType:               eInterfaces.EndpointType,
		DopplerLoggingEndpoint: epinio.epinioApiWsUrl,
	}

	return newCNSI, v2InfoResponse, nil
}

func (epinio *Epinio) UpdateMetadata(info *interfaces.Info, userGUID string, echoContext echo.Context) {
}

func (epinio *Epinio) loginHook(context echo.Context) error {
	log.Infof("Determining if user should auto-connect to %s.", epinio.epinioApiUrl)

	_, err := epinio.portalProxy.GetSessionStringValue(context, "user_id")
	if err != nil {
		return fmt.Errorf("could not determine user_id from session: %s", err)
	}

	epinioCnsi, err := epinio.portalProxy.GetCNSIRecordByEndpoint(epinio.epinioApiUrl)
	if err != nil {
		err := "could not find pre-registered epinio instance"
		log.Warnf(err)
		return errors.New(err)
	}

	log.Info("Auto-connecting to the auto-registered endpoint with credentials")
	_, err = epinio.portalProxy.DoLoginToCNSI(context, epinioCnsi.GUID, false)
	if err != nil {
		log.Warnf("Could not auto-connect using credentials to auto-registered endpoint: %s", err.Error())
		return err
	}
	return nil
}

func (epinio *Epinio) Connect(ec echo.Context, cnsiRecord interfaces.CNSIRecord, userId string) (*interfaces.TokenRecord, bool, error) {
	log.Info("Epinio Connect...")

	// These are set during log in
	username := ec.Get("rancher_username").(string)
	password := ec.Get("rancher_password").(string)

	if len(username) == 0 || len(password) == 0 {
		return nil, false, errors.New("username and/or password not present in context")
	}

	authString := fmt.Sprintf("%s:%s", username, password)
	base64EncodedAuthString := base64.StdEncoding.EncodeToString([]byte(authString))

	tr := &interfaces.TokenRecord{
		AuthType:     interfaces.AuthTypeHttpBasic,
		AuthToken:    base64EncodedAuthString,
		RefreshToken: username,
	}

	return tr, false, nil
}
