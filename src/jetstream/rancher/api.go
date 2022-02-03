package rancher

import (
	"encoding/json"
	"fmt"

	"github.com/epinio/ui-backend/stratos/src/jetstream/repository/interfaces"
	"github.com/labstack/echo/v4"
)

// Fetch settings
// /v1/management.cattle.io.setting
func MgmtSettings(ec echo.Context) error {

	// TODO: What the user sees depends on whether they are logged in

	col := NewDefaultSettings(ec)

	return sendResponse(ec, col)
}

// Get the available auth providers
func GetAuthProviders(ec echo.Context) error {
	col := NewAuthProvider(ec, "local")

	return sendResponse(ec, col)
}

func GetUser(ec echo.Context) error {
	user := NewUser(GetBaseURL(ec), "admin")

	return sendResponse(ec, user)
}

func TokenLogout(ec echo.Context) error {
	ec.Response().Header().Set("X-Api-Cattle-Auth", "false")

	ec.String(200, "OK")
	return nil
}

func GetPrincipals(ec echo.Context) error {
	principal := NewPrincipal(GetBaseURL(ec), "admin")

	return sendResponse(ec, principal)
}

func Login(authService interfaces.StratosAuth) echo.HandlerFunc {
	return func(ec echo.Context) error {
		return authService.Login((ec))
	}
}

func Clusters(ec echo.Context) error {
	col := Collection{
		Type:         CollectionType,
		ResourceType: ClusterResourceType,
		Actions:      make(map[string]string),
		Links:        make(map[string]string),
		Revision:     "1",
	}

	col.Links["self"] = GetSelfLink(ec)
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
