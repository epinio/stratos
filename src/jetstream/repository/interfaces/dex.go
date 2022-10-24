package interfaces

import (
	"context"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// OIDCProvider wraps an oidc.Provider and its Configuration
type OIDCProvider interface {
	// Issuer              string
	// Endpoint            *url.URL
	// Provider            *oidc.Provider
	// Config              *oauth2.Config
	// P                   PortalProxy
	AuthCodeURLWithPKCE() (string, string)
	AddScopes(scopes ...string)
	ExchangeWithPKCE(ctx context.Context, authCode, codeVerifier string) (*oauth2.Token, error)
	Verify(ctx context.Context, rawIDToken string) (*oidc.IDToken, error)

	GetConfig() *oauth2.Config
}
