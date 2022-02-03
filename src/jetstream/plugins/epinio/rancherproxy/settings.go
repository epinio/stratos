package rancherproxy

import (
	"fmt"

	"github.com/labstack/echo/v4"
)

func NewDefaultSettings(ec echo.Context) *Collection {
	col := Collection{
		Type:         CollectionType,
		ResourceType: SettingsResourceType,
		Actions:      make(map[string]string),
		Links:        make(map[string]string),
	}

	col.Links["self"] = GetSelfLink(ec)

	baseURL := GetSelfLink(ec)

	col.Data = make([]interface{}, 2)
	col.Data[0] = NewStringSettings(baseURL, "first-login", "false")
	col.Data[1] = NewStringSettings(baseURL, "ui-pl", "rancher")

	return &col
}

func NewStringSettings(baseURL, id, value string) *Setting {

	setting := Setting{}
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
