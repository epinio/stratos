package api

import (
	"encoding/json"
	"fmt"

	// "github.com/epinio/ui-backend/src/jetstream/repository/interfaces"
	"github.com/epinio/ui-backend/src/jetstream/plugins/epinio/rancherproxy/norman"
	"github.com/epinio/ui-backend/src/jetstream/plugins/epinio/rancherproxy/steve"

	"github.com/epinio/ui-backend/src/jetstream/plugins/epinio/rancherproxy/interfaces"
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
	user := norman.NewUser(interfaces.GetBaseURL(ec), "admin")

	return sendResponse(ec, user)
}

// /v3/authProviders
func TokenLogout(ec echo.Context) error {
	ec.Response().Header().Set("X-Api-Cattle-Auth", "false")

	ec.String(200, "OK")
	return nil
}

// /v3/authProviders
func GetPrincipals(ec echo.Context) error {
	principal := norman.NewPrincipal(interfaces.GetBaseURL(ec), "admin")

	return sendResponse(ec, principal)
}

// func Login(authService interfaces.StratosAuth) echo.HandlerFunc {
// 	return func(ec echo.Context) error {
// 		return authService.Login((ec))
// 	}
// }
// func EpinioLogin(authService interfaces.StratosAuth) echo.HandlerFunc {
// 	return func(ec echo.Context) error {
// 		return authService.Login((ec))
// 	}
// }

// /v1/management.cattle.io.cluster
func Clusters(ec echo.Context) error {
	col := steve.NewClusters(ec)
	// col := interfaces.Collection{
	// 	Type:         interfaces.CollectionType,
	// 	ResourceType: interfaces.ClusterResourceType,
	// 	Actions:      make(map[string]string),
	// 	Links:        make(map[string]string),
	// 	Revision:     "1",
	// }

	// col.Links["self"] = interfaces.GetSelfLink(ec)
	// col.Data = make([]interface{}, 0)
	// return nil

	return sendResponse(ec, col)


}

// /v1/schemas
func SteveSchemas(ec echo.Context) error {

	col := steve.NewDefaultSchemas(ec)

	return sendResponse(ec, col)

	// col := interfaces.Collection{
	// 	Type:         interfaces.CollectionType,
	// 	ResourceType: interfaces.SchemaType,
	// 	Actions:      make(map[string]string),
	// 	Links:        make(map[string]string),
	// 	Revision:     "1",
	// }

	// col.Links["self"] = interfaces.GetSelfLink(ec)
	// col.Data = make([]interface{}, 0)

	// sendResponse(ec, col)

	// return nil
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

	userID := ec.Get("user_id")
	isAuthenticated := userID != nil

	ec.Response().Header().Set("X-Api-Cattle-Auth", fmt.Sprintf("%t", isAuthenticated))
	ec.Response().Header().Set("Content-Type", "application/json")
	ec.Response().Status = 200
	ec.Response().Write([]byte(jsonString))

	return nil
}
