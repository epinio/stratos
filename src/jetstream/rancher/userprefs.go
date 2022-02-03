package rancher

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/labstack/echo/v4"
)

//go:embed default_prefs.json
var DefaultUserPreferences string

func NewUserPrefCollection() *Collection {
	col := Collection{
		Type:         CollectionType,
		ResourceType: UserPreferenceResourceType,
		Actions:      make(map[string]string),
		Links:        make(map[string]string),
	}

	return &col
}

func NewUserPref() *UserPref {
	pref := UserPref{
		Type:  UserPreferenceResourceType,
		ID:    UserPrefsID,
		Links: make(map[string]string),
	}

	return &pref
}

// Get user profile
func GetUserPrefs(c echo.Context) error {
	col := NewUserPrefCollection()
	data := json.RawMessage(DefaultUserPreferences)
	col.Data = make([]interface{}, 1)
	pref := NewUserPref()
	pref.Data = data
	col.Data[0] = pref

	host := GetBaseURL(c)
	base := fmt.Sprintf("https://%s%s", host, c.Request().URL.String())
	user := fmt.Sprintf("https://%s%s/%s", host, c.Request().URL.String(), UserPrefsID)

	col.Links["self"] = base
	pref.Links["self"] = user
	pref.Links["remove"] = user
	pref.Links["update"] = user

	return c.JSON(http.StatusOK, col)
}
