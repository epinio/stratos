package epinio

import (
	"errors"

	rancher "github.com/epinio/ui-backend/src/jetstream/plugins/epinio/rancherproxy/api"

	steve "github.com/epinio/ui-backend/src/jetstream/plugins/epinio/rancherproxy/steve"
	"github.com/epinio/ui-backend/src/jetstream/repository/interfaces"

	// "github.com/rancher/apiserver/pkg/types"
	// v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"

	"github.com/labstack/echo/v4"
	log "github.com/sirupsen/logrus"
)

const (
	tempEpinioApiUrl = "https://epinio.192.168.16.2.nip.io"
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

	epinioProxy := epinioGroup.Group("/proxy") // TODO: RC
	epinioProxy.Use(p.SetSecureCacheContentMiddleware)
	// epinioProxy.GET("/ping", epinio.ping) // TODO: RC REMOVE
	epinioProxy.GET("/*", epinio.EpinioProxyRequest) // TODO: RC REMOVE


	rancherProxy := epinioGroup.Group("/rancher")
	// Rancher Steve API
	steve := rancherProxy.Group("/v1")
	steve.Use(p.SetSecureCacheContentMiddleware)
	// steve.Use(p.SessionMiddleware()) // TODO: RC some of these should be secure (clear cache to see requests)
	steve.Use(func(h echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			userID, err := p.GetSessionValue(c, "user_id")
			if err == nil {
				c.Set("user_id", userID)
			}
			return h(c)
		}
	})
	steve.GET("/management.cattle.io.setting", rancher.MgmtSettings)

	steve.GET("/management.cattle.io.cluster", rancher.Clusters)// TODO: RC this shouldn't be needed before logging in
	steve.Use(p.SessionMiddleware())
	steve.GET("/schemas", rancher.SteveSchemas)
	steve.GET("/userpreferences", steve.GetUserPrefs) // TODO: RC this shouldn't be needed before logging in

	// Rancher Norman API
	norman := rancherProxy.Group("/v3")
	norman.Use(p.SetSecureCacheContentMiddleware)
	norman.Use(p.SessionMiddleware())

	norman.GET("/users", rancher.GetUser)
	norman.POST("/tokens", rancher.TokenLogout)
	norman.GET("/principals", rancher.GetPrincipals)
	steve.GET("/schemas", rancher.NormanSchemas)

	// Rancher Norman public API
	normanPublic := rancherProxy.Group("/v3-public")
	normanPublic.Use(p.SetSecureCacheContentMiddleware)
	normanPublic.POST("/authProviders/local/login", p.ConsoleLogin)
	normanPublic.GET("/authProviders", rancher.GetAuthProviders)



	// rancherShim := epinioGroup.Group("/rancher")
	// rancherShim.GET("/v1/management.cattle.io.setting", epinio.rancherMgmtSettings)


}

// Init performs plugin initialization
func (epinio *Epinio) Init() error {
	// TODO: RC Determine Epinio API url and store
	// epinio.portalProxy.AddAuthProvider(auth.InitGKEKubeAuth(c.portalProxy))

	return nil
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

