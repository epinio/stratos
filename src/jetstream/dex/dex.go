package dex

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/url"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/dchest/uniuri"
	"github.com/pkg/errors"
	"golang.org/x/oauth2"

	epinio_utils "github.com/epinio/ui-backend/src/jetstream/plugins/epinio/utils"
	jInterfaces "github.com/epinio/ui-backend/src/jetstream/repository/interfaces"
)

const (
	// https://dexidp.io/docs/custom-scopes-claims-clients/#public-clients
	OutOfBrowserURN = "urn:ietf:wg:oauth:2.0:oob"
	clientID        = "epinio-ui"
	clientSecret    = "jetstream-dex-epinio-ui" // Should match dex config for client
)

// https://github.com/epinio/epinio/blob/main/internal/dex/dex.go

var (
	// "openid" is a required scope for OpenID Connect flows.
	// Other scopes, such as "groups" can be requested. // TODO: RC name?
	DefaultScopes = []string{oidc.ScopeOpenID, oidc.ScopeOfflineAccess, "profile", "email", "groups"}
)

// OIDCProvider wraps an oidc.Provider and its Configuration
type OIDCProvider struct {
	Issuer   string
	Endpoint *url.URL
	Provider *oidc.Provider
	Config   *oauth2.Config
	P        jInterfaces.PortalProxy
}

func dexUrl(p jInterfaces.PortalProxy) (string, error) {
	// issuer := "http://dex.epinio.svc.cluster.local:5556" // TODO: RC this will be needed when deployed?
	epinioCnsi, err := epinio_utils.FindEpinioEndpoint(p)

	if err != nil {
		return "", err
	}

	authUrl := epinioCnsi.APIEndpoint.String()
	authUrl = strings.Replace(authUrl, "epinio.", "auth.", 1)
	return authUrl, nil
}

func createContext(p jInterfaces.PortalProxy, defaultCtx context.Context) (context.Context, error) {
	epinioCnsi, err := epinio_utils.FindEpinioEndpoint(p)

	if err != nil {
		return nil, err
	}

	if epinioCnsi.SkipSSLValidation {
		// https://github.com/golang/oauth2/issues/187#issuecomment-227811477
		tr := &http.Transport{
			Proxy:           http.ProxyFromEnvironment,
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		sslcli := &http.Client{Transport: tr}
		newctx := context.TODO()
		return context.WithValue(newctx, oauth2.HTTPClient, sslcli), nil
	}

	return defaultCtx, nil
}

// NewOIDCProvider construct an OIDCProvider fetching its configuration
func NewOIDCProvider(ctx context.Context, p jInterfaces.PortalProxy) (jInterfaces.OIDCProvider, error) {
	issuer, _ := dexUrl(p)
	endpoint, err := url.Parse(issuer)
	if err != nil {
		return nil, errors.Wrap(err, "parsing the issuer URL")
	}

	oidcProvider, err := NewOIDCProviderWithEndpoint(p, ctx, issuer, false, clientID, endpoint)
	if err != nil {
		return nil, err
	}

	oidcProvider.AddScopes("audience:server:client_id:epinio-api")

	return oidcProvider, nil
}

// NewOIDCProviderWithEndpoint construct an OIDCProvider fetching its configuration from the endpoint URL
func NewOIDCProviderWithEndpoint(p jInterfaces.PortalProxy, ctx context.Context, issuer string, issuerUnsecure bool, clientID string, endpoint *url.URL) (*OIDCProvider, error) {

	// If the issuer is different from the endpoint we need to set it in the context.
	// With this differentiation the Epinio server can reach the Dex service through the Kubernetes DNS
	// instead of the external URL. This was causing issues when the host was going to be resolved as a local IP (i.e: Rancher Desktop).
	// - https://github.com/epinio/epinio/issues/1781
	// if issuer != endpoint.String() && strings.HasSuffix(endpoint.Hostname(), ".svc.cluster.local") {
	// 	ctx = oidc.InsecureIssuerURLContext(ctx, issuer) // TODO: RC
	// }
	if issuerUnsecure {
		ctx = oidc.InsecureIssuerURLContext(ctx, issuer)
	}

	newCtx, err := createContext(p, ctx)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create context")
	}

	provider, err := oidc.NewProvider(newCtx, endpoint.String())
	if err != nil {
		return nil, errors.Wrap(err, "creating the provider")
	}

	config := &oauth2.Config{
		Endpoint:     provider.Endpoint(),
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  "https://localhost:8005/verify-auth", // TODO: RC
		Scopes:       DefaultScopes,
	}

	return &OIDCProvider{
		Issuer:   issuer,
		Endpoint: endpoint,
		Provider: provider,
		Config:   config,
		P:        p,
	}, nil
}

// AuthCodeURLWithPKCE will return an URL that can be used to obtain an auth code, and a code_verifier string.
// The code_verifier is needed to implement the PKCE auth flow, since this is going to be used by our CLI
// Ref: https://www.oauth.com/oauth2-servers/pkce/
func (pc *OIDCProvider) AuthCodeURLWithPKCE() (string, string) {
	state := uniuri.NewLen(32)
	codeVerifier := NewCodeVerifier()

	authCodeURL := pc.Config.AuthCodeURL(
		state,
		oauth2.SetAuthURLParam("code_verifier", codeVerifier.Value),
		oauth2.SetAuthURLParam("code_challenge", codeVerifier.ChallengeS256()),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	)

	return authCodeURL, codeVerifier.Value
}

// AddScopes will add scopes to the OIDCProvider.Config.Scopes, extending the DefaultScopes
func (pc *OIDCProvider) AddScopes(scopes ...string) {
	pc.Config.Scopes = append(pc.Config.Scopes, scopes...)
}

// ExchangeWithPKCE will exchange the authCode with a token, checking if the codeVerifier is valid
func (pc *OIDCProvider) ExchangeWithPKCE(ctx context.Context, authCode, codeVerifier string) (*oauth2.Token, error) {

	newCtx, err := createContext(pc.P, ctx)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create context")
	}

	token, err := pc.Config.Exchange(newCtx, authCode, oauth2.SetAuthURLParam("code_verifier", codeVerifier))
	if err != nil {
		return nil, errors.Wrap(err, "exchanging code for token")
	}
	return token, nil
}

// Verify will verify the token, and it will return an oidc.IDToken
func (pc *OIDCProvider) Verify(ctx context.Context, rawIDToken string) (*oidc.IDToken, error) {
	newCtx, err := createContext(pc.P, ctx)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create context")
	}

	keySet := oidc.NewRemoteKeySet(newCtx, pc.Endpoint.String()+"/keys")
	verifier := oidc.NewVerifier(pc.Issuer, keySet, &oidc.Config{ClientID: pc.Config.ClientID})

	token, err := verifier.Verify(newCtx, rawIDToken)
	if err != nil {
		return nil, errors.Wrap(err, "verifying rawIDToken")
	}
	return token, nil
}

func (pc OIDCProvider) GetConfig() *oauth2.Config {
	return pc.Config
}
