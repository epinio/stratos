package norman

import (
	"fmt"

	"github.com/labstack/echo/v4"
	"github.com/labstack/gommon/log"

	"github.com/epinio/ui-backend/src/jetstream/plugins/epinio/rancherproxy/interfaces"
	jInterfaces "github.com/epinio/ui-backend/src/jetstream/repository/interfaces"
)

func NewAuthProvider(ec echo.Context, id string) interfaces.AuthProvider {

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

	return ap
}

func NewAuthProviders(ec echo.Context, p jInterfaces.PortalProxy) (*interfaces.Collection, error) {
	col := interfaces.Collection{
		Type:         interfaces.CollectionType,
		ResourceType: interfaces.AuthProviderResourceType,
		Actions:      make(map[string]string),
		Links:        make(map[string]string),
	}

	col.Links["self"] = interfaces.GetSelfLink(ec)

	col.Data = make([]interface{}, 2)

	col.Data[0] = NewAuthProvider(ec, "local")

	oidc := NewAuthProvider(ec, "keycloakoidc")

	oidcProvider, err := p.GetDex()

	if err != nil {
		return nil, err
	}

	dexUrl, _ := oidcProvider.AuthCodeURLWithPKCE() // TODO: RC ooooof

	log.Warnf("NewAuthProviders: dexUrl: %+v", dexUrl)
	// client_id := "epinio-ui"
	// scope := "openid, offline_access, profile, email, groups, audience:server:client_id:epinio-api"
	// response_type := "code"

	// authUrl := dexUrl
	// authUrl = strings.Replace(authUrl, "epinio.", "auth.", 1)
	// authUrl += "/auth"
	// authUrl += "?client_id=" + client_id
	// authUrl += "&scope=" + scope
	// authUrl += "&response_type=" + response_type

	// This is what the frontend (with a bit of parsing, see auth store redirectTo) will redirect to when the user clicks log in
	oidc.RedirectUrl = dexUrl
	col.Data[1] = oidc
	// https://github.com/login/oauth/authorize?client_id=40099713a9fad881b5af

	// https://auth.134.122.107.58.nip.io/auth?

	// code_challenge=t_FsAmUcvA_hLkYhU69kPzT2gaAtOLyCDEkD72jMUpg&
	// code_challenge_method=S256&
	// code_verifier=lVhV3MqtSYzD5Nvlb39Q74OM6jCGyqat&
	// x HANDLED BY FRONTENT redirect_uri=http%3A%2F%2Flocalhost%3A45557&
	// done response_type=code&
	// done scope=openid+offline_access+profile+email+groups+audience%3Aserver%3Aclient_id%3Aepinio-api
	// done client_id=epinio-cli&
	// x HANDLED BY FRONTENT &state=WTjjACbFLgKz4f1mTgHhO16c6OXMHNIP

	// https://auth.134.122.107.58.nip.io/auth?
	//  client_id=epinio-ui&
	//  response_type=code&
	//  scope=openid%2Boffline_access%2Bprofile%2Bemail%2Bgroups%2Baudience%3Aserver%3Aclient_id%3Aepinio-api%2Copenid%20profile%20email&
	//  state=eyJub25jZSI6IlViRkRMWkJaQ0RZZTdpR2YiLCJ0byI6InZ1ZSIsInByb3ZpZGVyIjoia2V5Y2xvYWtvaWRjIn0&
	//  redirect_uri=https%3A%2F%2Flocalhost%3A8005%2Fverify-auth

	// https://auth.134.122.107.58.nip.io/auth?client_id=epinio-ui&response_type=code&scope=openid%2Coffline_access%2Cprofile%2Cemail%2Cgroups%2Caudience%3Aserver%3Aclient_id%3Aepinio-api%2Copenid%20profile%20email&state=eyJub25jZSI6InJDZnoyRzFSU2tKbWkwOFEiLCJ0byI6InZ1ZSIsInByb3ZpZGVyIjoia2V5Y2xvYWtvaWRjIn0&redirect_uri=https%3A%2F%2Flocalhost%3A8005%2Fverify-auth

	return &col, nil
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
		ID:                 fmt.Sprintf("%s", name),
		UUID:               fmt.Sprintf("%s", name),
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
		ID:            fmt.Sprintf("local://%s", name),
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

	col.Data = make([]interface{}, 1)
	col.Data[0] = principal

	return &col
}
