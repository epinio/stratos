package epinio

import (
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
	tempEpinioApiUrl = "https://epinio.192.168.16.2.nip.io"
	EndpointType  = "epinio"
)

// Epinio - Plugin to TODO: RC
type Epinio struct {
	portalProxy    interfaces.PortalProxy
	epinioApiUrl   string
}

func init() {
	interfaces.AddPlugin("epinio", nil, Init)
}

// Init creates a new Analysis
func Init(portalProxy interfaces.PortalProxy) (interfaces.StratosPlugin, error) {
	// store.InitRepositoryProvider(portalProxy.GetConfig().DatabaseProviderName)
	return &Epinio{
		portalProxy: portalProxy,
		epinioApiUrl: tempEpinioApiUrl,
	}, nil
}

// GetMiddlewarePlugin gets the middleware plugin for this plugin
func (epinio *Epinio) GetMiddlewarePlugin() (interfaces.MiddlewarePlugin, error) {
	return nil, errors.New("Not implemented")
}

// GetEndpointPlugin gets the endpoint plugin for this plugin
func (epinio *Epinio) GetEndpointPlugin() (interfaces.EndpointPlugin, error) {
	return nil, errors.New("Not implemented")
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





}

// Init performs plugin initialization
func (epinio *Epinio) Init() error {
	// TODO: RC Determine Epinio API url and store
	// epinio.portalProxy.AddAuthProvider(auth.InitGKEKubeAuth(c.portalProxy))

	cnsiName := "default"
	apiEndpoint := epinio.epinioApiUrl
	skipSSLValidation := true
	fetchInfo := epinio.Info

	epinioCnsi, err := epinio.portalProxy.DoRegisterEndpoint(cnsiName, apiEndpoint, skipSSLValidation, "", "", false, "", fetchInfo)
	log.Infof("Auto-registering epinio endpoint %s as \"%s\" (%s)", apiEndpoint, cnsiName, epinioCnsi.GUID)

	if err != nil {
		log.Errorf("Could not auto-register Epinio endpoint: %v. %v", err, epinioCnsi)
		return nil
	}
	log.Errorf("AUTO REGISTERED: %+v", epinioCnsi)//TODO: RC REMOVE

	// Add login hook to automatically register and connect to the Cloud Foundry when the user logs in
	epinio.portalProxy.AddLoginHook(0, epinio.loginHook)

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

func (epinio *Epinio) loginHook(context echo.Context) error {


	log.Infof("Determining if user should auto-connect to %s.", epinio.epinioApiUrl)

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

	// userID, err := p.GetSessionStringValue(c, "user_id")
	// if err != nil {
	// 	return nil, echo.NewHTTPError(http.StatusUnauthorized, "Could not find correct session value")
	// }

	// TODO: RC error handling
	sTokenRecord, ok := epinio.portalProxy.GetCNSITokenRecord("STRATOS", userId)
	if !ok {
		log.Warnf("Could not fetch stratos log in token")
		return nil, false, errors.New("Could not fetch stratos log in token")
	}

	return &sTokenRecord, false, nil


	// TODO: RC remove (old way, create auth connect bearer token)
	// params := new(interfaces.LoginToCNSIParams)
	// err := interfaces.BindOnce(params, ec)
	// if err != nil {
	// 	return nil, false, err
	// }

	// connectType := params.ConnectType
	// if len(connectType) == 0 {
	// 	connectType = interfaces.AuthConnectTypeBearer
	// }

	// if connectType != interfaces.AuthConnectTypeBearer {
	// 	return nil, false, errors.New("Only bearer token accepted for Epinio endpoints")
	// }

	// tokenRec = &interfaces.TokenRecord{
	// 	AuthToken:     "asdsad", // TODO: RC
	// 	AuthType:       interfaces.AuthTypeBearer,
	// }
	// tokenRecord, err := c.portalProxy.ConnectOAuth2(ec, cnsiRecord)
	// if err != nil {
	// 	return nil, false, err
	// }


	// return tokenRecord, cfAdmin, nil
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

