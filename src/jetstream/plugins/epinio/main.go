package epinio

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	rancherProxy "github.com/epinio/ui-backend/src/jetstream/plugins/epinio/rancherproxy/api"
	steveProxy "github.com/epinio/ui-backend/src/jetstream/plugins/epinio/rancherproxy/steve"

	"github.com/epinio/ui-backend/src/jetstream/repository/interfaces"

	"github.com/labstack/echo/v4"
	log "github.com/sirupsen/logrus"
)

// TODO: RC POST FAILS with 401
// TODO: RC user avatar menu (get correct user, remove parts can't use)
// TODO: RC check - update token on each log in
// TODO: RC non-cde
// 1) update package.json

const (
	// TODO: RC These should come from env or be calculated - https://github.com/epinio/ui/issues/69. Could be done in init or Init?
	tempEpinioApiUrl = "https://epinio.172.22.0.2.nip.io"
	tempEpinioApiUrlskipSSLValidation = true
	EndpointType  = "epinio"
)

// Epinio - Plugin
type Epinio struct {
	portalProxy    interfaces.PortalProxy
	epinioApiUrl   string
	epinioApiUrlskipSSLValidation bool
}

func init() {
	interfaces.AddPlugin(EndpointType, nil, Init)
}

// Init creates a new Analysis
func Init(portalProxy interfaces.PortalProxy) (interfaces.StratosPlugin, error) {
	return &Epinio{
		portalProxy: portalProxy,
		epinioApiUrl: tempEpinioApiUrl,
		epinioApiUrlskipSSLValidation: tempEpinioApiUrlskipSSLValidation,
	}, nil
}

func (epinio *Epinio) createMiddleware() echo.MiddlewareFunc {
	return func(h echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {

			req := c.Request() // TODO: RC fires on all requests

			req.Header.Set("x-cap-cnsi-list", "rAgj2mNgfUEHq6N90b86azw8gbs")
			req.Header.Set("x-cap-passthrough", "true")

			return h(c)
		}
	}
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
		if strings.HasPrefix(c.Request().URL.String(), "/pp/v1/proxy/") {
			req := c.Request()

			if epinioCnsi, err := epinio.findEpinioEndpoint(); err == nil {
				req.Header.Set("x-cap-cnsi-list", epinioCnsi.GUID)
				req.Header.Set("x-cap-passthrough", "true")
			} else {
				log.Warn("Failed to find Epinio Endpoint to proxy to. This will probably cause many requests to fail")
			}
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
	return EndpointType
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
	// steve.Use(p.SessionMiddleware()) // TODO: RC some of these should be secure (clear cache to see requests)
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
	steveGroup.GET("/management.cattle.io.setting", rancherProxy.MgmtSettings)

	steveGroup.GET("/management.cattle.io.cluster", rancherProxy.Clusters)// TODO: RC this shouldn't be needed before logging in
	steveGroup.Use(p.SessionMiddleware())
	steveGroup.GET("/schemas", rancherProxy.SteveSchemas)
	steveGroup.GET("/userpreferences", steveProxy.GetUserPrefs) // TODO: RC this shouldn't be needed before logging in
	steveGroup.PUT("/userpreferences/*", steveProxy.GetSpecificUserPrefs) // TODO: RC what's being sent, and why?

	// Rancher Norman API
	normanGroup := rancherProxyGroup.Group("/v3")
	normanGroup.Use(p.SetSecureCacheContentMiddleware)
	normanGroup.Use(p.SessionMiddleware())
	normanGroup.GET("/users", rancherProxy.GetUser)
	normanGroup.POST("/tokens", rancherProxy.TokenLogout)
	normanGroup.GET("/principals", rancherProxy.GetPrincipals)
	normanGroup.GET("/schemas", rancherProxy.NormanSchemas)

	// Rancher Norman public API
	normanPublicGroup := rancherProxyGroup.Group("/v3-public")
	normanPublicGroup.Use(p.SetSecureCacheContentMiddleware)
	normanPublicGroup.POST("/authProviders/local/login", p.ConsoleLogin)
	normanPublicGroup.GET("/authProviders", rancherProxy.GetAuthProviders)


	// /v1/subscribe // TODO: RC


}

func (epinio *Epinio) findEpinioEndpoint() (*interfaces.CNSIRecord, error) {
	endpoints, err := epinio.portalProxy.ListEndpoints()
	if err != nil {
		msg := "Failed to fetch list of endpoints: %+v"
		log.Errorf(msg, err)
		return nil, fmt.Errorf(msg, err)
	}

	var epinioEndpoint *interfaces.CNSIRecord
	for _, e := range endpoints {
		if e.CNSIType == "epinio" { // TODO: RC un-hardcode
			epinioEndpoint = e
			break;
		}
	}

	if epinioEndpoint == nil {
		msg := "Failed to find an epinio endpoint"
		log.Error(msg)
		return nil, fmt.Errorf(msg)
	}

	return epinioEndpoint, nil
}

// Init performs plugin initialization
func (epinio *Epinio) Init() error {
	// Add login hook to automatically register and connect to the Cloud Foundry when the user logs in
	epinio.portalProxy.AddLoginHook(0, epinio.loginHook)

	// TODO: RC Determine Epinio API url and store
	// epinio.portalProxy.AddAuthProvider(auth.InitGKEKubeAuth(c.portalProxy))

	cnsiName := "epinio_default"
	apiEndpoint := epinio.epinioApiUrl
	skipSSLValidation := epinio.epinioApiUrlskipSSLValidation
	fetchInfo := epinio.Info

	// TODO: RC find first... if not there then add
	if epinioCnsi, err := epinio.findEpinioEndpoint(); err == nil {
		log.Infof("Skipping auto-registration of epinio endpoint %s (exists as \"%s\" (%s)", apiEndpoint, cnsiName, epinioCnsi.GUID)
	} else {
		epinioCnsi, err := epinio.portalProxy.DoRegisterEndpoint(cnsiName, apiEndpoint, skipSSLValidation, "", "", false, "", fetchInfo)
		log.Infof("Auto-registering epinio endpoint %s as \"%s\" (%s)", apiEndpoint, cnsiName, epinioCnsi.GUID)

		if err != nil {
			log.Errorf("Could not auto-register Epinio endpoint: %v. %+v", err, epinioCnsi)
			return nil
		}
	}

	return nil
}

func (epinio *Epinio) Info(apiEndpoint string, skipSSLValidation bool) (interfaces.CNSIRecord, interface{}, error) {
	log.Debug("Info")
	v2InfoResponse := interfaces.V2Info{}

	newCNSI := interfaces.CNSIRecord{
		CNSIType: EndpointType,
	}

	return newCNSI, v2InfoResponse, nil
}

func (epinio *Epinio) UpdateMetadata(info *interfaces.Info, userGUID string, echoContext echo.Context) {
}

func (epinio *Epinio) loginHook(context echo.Context) error {


	log.Infof("Determining if user should auto-connect to %s.", epinio.epinioApiUrl)


	log.Errorf("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!Determining if user should auto-connect to %s.", epinio.epinioApiUrl) // TODO: RC

	_, err := epinio.portalProxy.GetSessionStringValue(context, "user_id")
	if err != nil {
		return fmt.Errorf("Could not determine user_id from session: %s", err)
	}

	epinioCnsi, err := epinio.portalProxy.GetCNSIRecordByEndpoint(epinio.epinioApiUrl)
	if err != nil {
		err:="Could not find pre-registered epinio instance"
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
		return nil, false, errors.New("Username and/or password not present in context")
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


