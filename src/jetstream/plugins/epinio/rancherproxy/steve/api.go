package steve

import (
	"encoding/json"
	"fmt"

	"github.com/epinio/ui-backend/src/jetstream/plugins/epinio/rancherproxy/api"

	"github.com/labstack/echo/v4"
)

// Fetch settings
// /v1/management.cattle.io.setting
func MgmtSettings(ec echo.Context) error {

	// TODO: What the user sees depends on whether they are logged in

	col := NewDefaultSettings(ec)

	return api.SendResponse(ec, col)
}

// /v1/management.cattle.io.cluster
func Clusters(ec echo.Context) error {
	col := NewClusters(ec)

	return api.SendResponse(ec, col)
}

// /v1/schemas
func SteveSchemas(ec echo.Context) error {

	col := NewDefaultSchemas(ec)

	return api.SendResponse(ec, col)
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
