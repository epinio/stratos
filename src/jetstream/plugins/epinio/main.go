package analysis

import (
	"errors"
	"encoding/json"
	"net/http"

	"github.com/epinio/ui-backend/src/jetstream/repository/interfaces"
	"github.com/rancher/apiserver/pkg/types"

	// v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"

	"github.com/labstack/echo/v4"
	log "github.com/sirupsen/logrus"
)

const (
	tempEpinioApiUrl = "https://epinio.192.168.16.2.nip.io"
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
	echoGroup.GET("/ping", epinio.ping)

	epinioGroup := echoGroup.Group("/epinio")
	epinioGroup.GET("/ping", epinio.ping)

	rancherShim := epinioGroup.Group("/rancher")
	rancherShim.GET("/v1/management.cattle.io.setting", epinio.rancherMgmtSettings)
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

func (epinio *Epinio) rancherMgmtSettings(ec echo.Context) error {
	log.Debug("epinio management.cattle.io.setting")// TODO: RC Remove

	b := []byte(`{"Name":"Wednesday","Age":6,"Parents":["Gomez","Morticia"]}`)
	var firstLogin *types.RawResource
	if err := json.Unmarshal(b, &firstLogin); err != nil {
		return echo.NewHTTPError(http.StatusForbidden, err.Error()) // TODO: RC
	}

	res, err := epinio.rancherCreateListResponse([]*types.RawResource { firstLogin }, "management.cattle.io.setting")
	if err != nil {
		return echo.NewHTTPError(http.StatusForbidden, err.Error())
	}

	return ec.JSON(200, res)
}


func (epinio *Epinio) rancherCreateListResponse(data []*types.RawResource, resourceType string) (types.GenericCollection, error) {

	res := types.GenericCollection{
		Collection: types.Collection{
			Type: "collection",
			Links: map[string]string{
				"self": "https://rancher.richardcox.dev/v1/" + resourceType, // TODO: RC
			},
			Actions: map[string]string{},
			ResourceType: resourceType,
			Revision: "1",
		},
		Data: data,
	}

	return res, nil;
}
