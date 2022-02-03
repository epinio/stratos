package rancherproxy

import (
	"fmt"

	"github.com/labstack/echo/v4"
)

func NewAuthProvider(ec echo.Context, id string) *Collection {
	col := Collection{
		Type:         CollectionType,
		ResourceType: AuthProviderResourceType,
		Actions:      make(map[string]string),
		Links:        make(map[string]string),
	}

	col.Links["self"] = GetSelfLink(ec)

	typ := fmt.Sprintf("%sProvider", id)

	ap := AuthProvider{
		ID:       id,
		BaseType: AuthProviderResourceType,
		Type:     typ,
		Actions:  make(map[string]string),
		Links:    make(map[string]string),
	}

	ap.Links["self"] = GetSelfLink(ec, id)
	ap.Actions["login"] = GetSelfLink(ec, id, "login")

	col.Data = make([]interface{}, 1)
	col.Data[0] = ap

	return &col
}

func NewUser(baseURL, name string) *Collection {
	col := Collection{
		Type:         CollectionType,
		ResourceType: UserResourceType,
		Actions:      make(map[string]string),
		Links:        make(map[string]string),
	}

	col.Links["self"] = baseURL

	user := User{
		ID:                 fmt.Sprintf("user-id-%s", name),
		UUID:               fmt.Sprintf("user-id-%s", name),
		BaseType:           UserResourceType,
		Type:               UserResourceType,
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

func NewPrincipal(baseURL, name string) *Collection {
	col := Collection{
		Type:         CollectionType,
		ResourceType: PrincipalResourceType,
		Actions:      make(map[string]string),
		Links:        make(map[string]string),
	}

	col.Links["self"] = baseURL

	principal := Principal{
		ID:            fmt.Sprintf("local://user-id-%s", name),
		BaseType:      PrincipalResourceType,
		Type:          PrincipalResourceType,
		PrincipalType: UserResourceType,
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
