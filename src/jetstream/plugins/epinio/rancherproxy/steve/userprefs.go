package steve

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/epinio/ui-backend/src/jetstream/plugins/epinio/rancherproxy/interfaces"

	"github.com/labstack/echo/v4"
)

//go:embed default_prefs.json
var DefaultUserPreferences string

func NewUserPrefCollection() *interfaces.Collection {
	col := interfaces.Collection{
		Type:         interfaces.CollectionType,
		ResourceType: interfaces.UserPreferenceResourceType,
		Actions:      make(map[string]string),
		Links:        make(map[string]string),
	}

	return &col
}

func NewUserPref() *interfaces.UserPref {
	pref := interfaces.UserPref{
		Type:  interfaces.UserPreferenceResourceType,
		ID:    interfaces.UserPrefsID,
		Links: make(map[string]string),
	}

	return &pref
}

// Get user profile
// func GetUserPrefs(c echo.Context) error {
// 	col := NewUserPrefCollection()
// 	data := json.RawMessage(DefaultUserPreferences)
// 	col.Data = make([]interface{}, 1)
// 	pref := NewUserPref()
// 	pref.Data = data
// 	col.Data[0] = pref

// 	host := interfaces.GetBaseURL(c)
// 	base := fmt.Sprintf("https://%s%s", host, c.Request().URL.String())
// 	user := fmt.Sprintf("https://%s%s/%s", host, c.Request().URL.String(), interfaces.UserPrefsID)

// 	col.Links["self"] = base
// 	pref.Links["self"] = user
// 	pref.Links["remove"] = user
// 	pref.Links["update"] = user

// 	return c.JSON(http.StatusOK, col)
// }
func GetUserPrefs(c echo.Context) error {
	col := NewUserPrefCollection()
	col.Data = make([]interface{}, 1)
	pref := createPref(c)
	col.Data[0] = pref

	host := interfaces.GetBaseURL(c)
	base := fmt.Sprintf("https://%s%s", host, c.Request().URL.String())

	col.Links["self"] = base

	return c.JSON(http.StatusOK, col)
}

// Get user profile
func GetSpecificUserPrefs(c echo.Context) error {
	return c.JSON(http.StatusOK, createPref(c))
}

func createPref(c echo.Context) *interfaces.UserPref {
	data := json.RawMessage(DefaultUserPreferences)
	pref := NewUserPref()
	pref.Data = data

	host := interfaces.GetBaseURL(c)
	user := fmt.Sprintf("https://%s%s/%s", host, c.Request().URL.String(), interfaces.UserPrefsID)

	pref.Links["self"] = user
	pref.Links["remove"] = user
	pref.Links["update"] = user

	return pref
}
