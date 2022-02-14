package steve

import (
	"fmt"

	"github.com/labstack/echo/v4"

	"github.com/epinio/ui-backend/src/jetstream/plugins/epinio/rancherproxy/interfaces"
)

func NewDefaultSettings(ec echo.Context) *interfaces.Collection {
	col := interfaces.Collection{
		Type:         interfaces.CollectionType,
		ResourceType: interfaces.SettingsResourceType,
		Actions:      make(map[string]string),
		Links:        make(map[string]string),
	}

	col.Links["self"] = interfaces.GetSelfLink(ec)

	baseURL := interfaces.GetSelfLink(ec)

	col.Data = make([]interface{}, 2)
	// Visible to all, regardless of auth
	col.Data[0] = NewStringSettings(baseURL, "first-login", "false")
	col.Data[1] = NewStringSettings(baseURL, "ui-pl", "Epinio")

	return &col
}

func NewStringSettings(baseURL, id, value string) *interfaces.Setting {

	setting := interfaces.Setting{}
	setting.ID = id
	setting.APIVersion = "management.cattle.io/v3"
	setting.Kind = "Setting"
	setting.Type = "management.cattle.io.setting"
	setting.Customized = false
	setting.Default = value
	setting.Value = value
	setting.Links = make(map[string]string)
	setting.Links["self"] = fmt.Sprintf("%s/%s", baseURL, id)

	return &setting
}
