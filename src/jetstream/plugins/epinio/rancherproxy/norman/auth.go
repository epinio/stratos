package norman

import (
	"fmt"

	"github.com/labstack/echo/v4"

	"github.com/epinio/ui-backend/src/jetstream/plugins/epinio/rancherproxy/interfaces"
)

func NewAuthProvider(ec echo.Context, id string) *interfaces.Collection {
	col := interfaces.Collection{
		Type:         interfaces.CollectionType,
		ResourceType: interfaces.AuthProviderResourceType,
		Actions:      make(map[string]string),
		Links:        make(map[string]string),
	}

	col.Links["self"] = interfaces.GetSelfLink(ec)

	typ := fmt.Sprintf("%sProvider", id)

	ap := interfaces.AuthProvider{
		ID:       id,
		BaseType: interfaces.AuthProviderResourceType,
		Type:     typ,
		Actions:  make(map[string]string),
		Links:    make(map[string]string),
	}

	ap.Links["self"] = interfaces.GetSelfLink(ec, id)
	ap.Actions["login"] = interfaces.GetSelfLink(ec, id, "login")

	col.Data = make([]interface{}, 1)
	col.Data[0] = ap

	return &col
}

func NewUser(baseURL, name string) *interfaces.Collection {
	col := interfaces.Collection{
		Type:         interfaces.CollectionType,
		ResourceType: interfaces.UserResourceType,
		Actions:      make(map[string]string),
		Links:        make(map[string]string),
	}

	col.Links["self"] = baseURL

	user := interfaces.User{
		ID:                 fmt.Sprintf("user-id-%s", name),
		UUID:               fmt.Sprintf("user-id-%s", name),
		BaseType:           interfaces.UserResourceType,
		Type:               interfaces.UserResourceType,
		Username:           name,
		Description:        "",
		Me:                 true,
		Enabled:            true,
		MustChangePassword: false,
		Name:               name,
		State:              "active",
		Actions:            make(map[string]string),
		Links:              make(map[string]string),
	}

	user.PrinicpalIDs = make([]string, 1)
	user.PrinicpalIDs[0] = fmt.Sprintf("local://%s", user.ID)

	//user.Links["self"] = GetSelfLink(ec, id)
	//user.Actions["login"] = GetSelfLink(ec, id, "login")

	col.Data = make([]interface{}, 1)
	col.Data[0] = user

	return &col
}

func NewPrincipal(baseURL, name string) *interfaces.Collection {
	col := interfaces.Collection{
		Type:         interfaces.CollectionType,
		ResourceType: interfaces.PrincipalResourceType,
		Actions:      make(map[string]string),
		Links:        make(map[string]string),
	}

	col.Links["self"] = baseURL

	principal := interfaces.Principal{
		ID:            fmt.Sprintf("local://user-id-%s", name),
		BaseType:      interfaces.PrincipalResourceType,
		Type:          interfaces.PrincipalResourceType,
		PrincipalType: interfaces.UserResourceType,
		LoginName:     name,
		Me:            true,
		MemberOf:      false,
		Name:          name,
		Provider:      "local",
		Actions:       make(map[string]string),
		Links:         make(map[string]string),
	}

	//user.Links["self"] = GetSelfLink(ec, id)
	//user.Actions["login"] = GetSelfLink(ec, id, "login")

	col.Data = make([]interface{}, 1)
	col.Data[0] = principal

	return &col
}
