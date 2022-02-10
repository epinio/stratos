package api

import (
	"encoding/json"
	"fmt"

	log "github.com/sirupsen/logrus"

	// "github.com/epinio/ui-backend/src/jetstream/repository/interfaces"
	"github.com/epinio/ui-backend/src/jetstream/plugins/epinio/rancherproxy/norman"
	"github.com/epinio/ui-backend/src/jetstream/plugins/epinio/rancherproxy/steve"

	"github.com/epinio/ui-backend/src/jetstream/plugins/epinio/rancherproxy/interfaces"
	jInterfaces "github.com/epinio/ui-backend/src/jetstream/repository/interfaces"

	"github.com/labstack/echo/v4"
)

// Fetch settings
// /v1/management.cattle.io.setting
func MgmtSettings(ec echo.Context) error {

	// TODO: What the user sees depends on whether they are logged in

	col := steve.NewDefaultSettings(ec)

	return sendResponse(ec, col)
}

// Get the available auth providers
// /v3/authProviders
func GetAuthProviders(ec echo.Context) error {
	col := norman.NewAuthProvider(ec, "local")

	return sendResponse(ec, col)
}

// /v3/authProviders
func GetUser(ec echo.Context) error {
	user := norman.NewUser(interfaces.GetBaseURL(ec), ec.Get("user_id").(string))

	return sendResponse(ec, user)
}

// /v3/users
func TokenLogout(ec echo.Context, p jInterfaces.PortalProxy) error {
	ec.Response().Header().Set("X-Api-Cattle-Auth", "false")
	return p.ConsoleLogout(ec)
}

// /v3/principals
func GetPrincipals(ec echo.Context) error {
	principal := norman.NewPrincipal(interfaces.GetBaseURL(ec), ec.Get("user_id").(string))

	return sendResponse(ec, principal)
}

// /v1/management.cattle.io.cluster
func Clusters(ec echo.Context) error {
	col := steve.NewClusters(ec)

	return sendResponse(ec, col)
}

// /v1/schemas
func SteveSchemas(ec echo.Context) error {

	col := steve.NewDefaultSchemas(ec)

	return sendResponse(ec, col)
}

// /v3/schemas
func NormanSchemas(ec echo.Context) error {
	// TODO: RC make collection create common
	col := interfaces.Collection{
		Type:         interfaces.CollectionType,
		ResourceType: interfaces.SchemaType,
		Actions:      make(map[string]string),
		Links:        make(map[string]string),
		Revision:     "1",
	}

	col.Links["self"] = interfaces.GetSelfLink(ec)
	col.Data = make([]interface{}, 0)

	sendResponse(ec, col)

	return nil
}

func sendResponse(ec echo.Context, obj interface{}) error {
	jsonString, err := json.Marshal(obj)
	if err != nil {
		return err
	}

	userID := ec.Get("user_id") // TODO: RC userID, err := p.GetSessionValue(c, "user_id")
	isAuthenticated := userID != nil

	ec.Response().Header().Set("X-Api-Cattle-Auth", fmt.Sprintf("%t", isAuthenticated))
	ec.Response().Header().Set("Content-Type", "application/json")
	ec.Response().Status = 200
	ec.Response().Write([]byte(jsonString))

	return nil
}
