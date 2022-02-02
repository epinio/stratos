package analysis

import (
	"errors"

	"github.com/epinio/ui-backend/src/jetstream/repository/interfaces"

	"github.com/labstack/echo/v4"
	log "github.com/sirupsen/logrus"
)

const (
)

// Analysis - Plugin to allow analysers to run over an endpoint cluster
type Epinio struct {
	portalProxy    interfaces.PortalProxy
	// analysisServer string
}

// []string{"kubernetes"}
func init() {
	interfaces.AddPlugin("epinio", nil, Init)
}

// Init creates a new Analysis
func Init(portalProxy interfaces.PortalProxy) (interfaces.StratosPlugin, error) {
	// store.InitRepositoryProvider(portalProxy.GetConfig().DatabaseProviderName)
	return &Epinio{portalProxy: portalProxy}, nil
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
	epinioGroup := echoGroup.Group("/epinio")
	epinioGroup.GET("/ping", epinio.ping)
}

// Init performs plugin initialization
func (epinio *Epinio) Init() error {
	// TODO: RC Determine Epinio API url and store

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
