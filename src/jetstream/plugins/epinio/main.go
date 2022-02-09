package epinio

import (
	"encoding/base64"
	"errors"
	"fmt"

	rancherProxy "github.com/epinio/ui-backend/src/jetstream/plugins/epinio/rancherproxy/api"

	steveProxy "github.com/epinio/ui-backend/src/jetstream/plugins/epinio/rancherproxy/steve"
	"github.com/epinio/ui-backend/src/jetstream/repository/interfaces"

	// "github.com/rancher/apiserver/pkg/types"
	// v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"

	"github.com/labstack/echo/v4"
	log "github.com/sirupsen/logrus"
)

const (
	// TODO: RC these should be calculated (find github issue number)
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
	// store.InitRepositoryProvider(portalProxy.GetConfig().DatabaseProviderName)
	return &Epinio{
		portalProxy: portalProxy,
		epinioApiUrl: tempEpinioApiUrl,
		epinioApiUrlskipSSLValidation: tempEpinioApiUrlskipSSLValidation,
	}, nil
}

// GetMiddlewarePlugin gets the middleware plugin for this plugin
func (epinio *Epinio) GetMiddlewarePlugin() (interfaces.MiddlewarePlugin, error) {
	return nil, errors.New("Not implemented")
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
	echoGroup.GET("/ping", epinio.ping) // TODO: RC REMOVE

	epinioGroup := echoGroup.Group("/epinio")

	p := epinio.portalProxy

	epinioProxyGroup := epinioGroup.Group("/proxy")
	epinioProxyGroup.Use(p.SetSecureCacheContentMiddleware)
	epinioProxyGroup.Use(func(h echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			userID, err := p.GetSessionValue(c, "user_id")
			if err == nil {
				c.Set("user_id", userID)
			}
			return h(c)
		}
	})
	epinioProxyGroup.GET("/*", epinio.EpinioProxyRequest)


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


	// /v1/subscribe


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

	epinioCnsi, err := epinio.portalProxy.DoRegisterEndpoint(cnsiName, apiEndpoint, skipSSLValidation, "", "", false, "", fetchInfo)
	log.Infof("Auto-registering epinio endpoint %s as \"%s\" (%s)", apiEndpoint, cnsiName, epinioCnsi.GUID)

	if err != nil {
		log.Errorf("Could not auto-register Epinio endpoint: %v. %+v", err, epinioCnsi)
		return nil
	}
	log.Errorf("AUTO REGISTERED: %+v", epinioCnsi)//TODO: RC REMOVE



	return nil
}

func (epinio *Epinio) Info(apiEndpoint string, skipSSLValidation bool) (interfaces.CNSIRecord, interface{}, error) {
	log.Debug("Info")
	v2InfoResponse := interfaces.V2Info{}

	newCNSI := interfaces.CNSIRecord{
		CNSIType: EndpointType,
	}

	// uri, err := url.Parse(apiEndpoint)
	// if err != nil {
	// 	return newCNSI, nil, err
	// }

	// uri.Path = "v2/info"
	// h := c.portalProxy.GetHttpClient(skipSSLValidation)

	// res, err := h.Get(uri.String())
	// if err != nil {
	// 	return newCNSI, nil, err
	// }

	// if res.StatusCode != 200 {
	// 	buf := &bytes.Buffer{}
	// 	io.Copy(buf, res.Body)
	// 	defer res.Body.Close()

	// 	return newCNSI, nil, fmt.Errorf("%s endpoint returned %d\n%s", uri.String(), res.StatusCode, buf)
	// }

	// dec := json.NewDecoder(res.Body)
	// if err = dec.Decode(&v2InfoResponse); err != nil {
	// 	return newCNSI, nil, err
	// }

	// newCNSI.TokenEndpoint = v2InfoResponse.TokenEndpoint
	// newCNSI.AuthorizationEndpoint = v2InfoResponse.AuthorizationEndpoint
	// newCNSI.DopplerLoggingEndpoint = v2InfoResponse.DopplerLoggingEndpoint

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

func (epinio *Epinio) ping(ec echo.Context) error {
	// TODO: RC Remove
	log.Debug("epinio ping")

	var response struct {
		Status   int
	}
	response.Status = 1;

	return ec.JSON(200, response)
}

