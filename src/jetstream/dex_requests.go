package main

import (
	"fmt"
	"net/http"
	"time"

	"github.com/epinio/ui-backend/src/jetstream/dex"
	"github.com/epinio/ui-backend/src/jetstream/repository/interfaces"
	log "github.com/sirupsen/logrus"
	"golang.org/x/net/context"
	"golang.org/x/oauth2"
)

func (p *portalProxy) DoDexFlowRequest(cnsiRequest *interfaces.CNSIRequest, req *http.Request) (*http.Response, error) {
	log.Debug("DoDexFlowRequest")

	// client.New(context.Background(), &settings.Settings{API: srv.URL})
	// oidcProvider, _ := dex.NewOIDCProvider(req.Context(), p) // TODO: RC do only once

	// tokenRec, cnsi, err := p.getCNSIRequestRecords(cnsiRequest)
	// userToken, ok := p.GetCNSITokenRecordWithDisconnected(cnsiRequest.GUID, cnsiRequest.UserGUID)
	// if !ok {
	// 	return nil, fmt.Errorf("Info could not be found for user with GUID %s")
	// }
	// t := &oauth2.Token{
	// 	AccessToken:  userToken.AuthToken,
	// 	TokenType:    "Bearer",
	// 	RefreshToken: userToken.RefreshToken,
	// 	Expiry:       time.Unix(userToken.TokenExpiry, 0),
	// }
	// Not not secure!
	// client := oidcProvider.Config.Client(req.Context(), t) // TODO: Error

	// return client.Do(req)

	// AccessToken string `json:"access_token"`

	// // TokenType is the type of token.
	// // The Type method returns either this or "Bearer", the default.
	// TokenType string `json:"token_type,omitempty"`

	// // RefreshToken is a token that's used by the application
	// // (as opposed to the user) to refresh the access token
	// // if it expires.
	// RefreshToken string `json:"refresh_token,omitempty"`

	// // Expiry is the optional expiration time of the access token.
	// //
	// // If zero, TokenSource implementations will reuse the same
	// // token forever and RefreshToken or equivalent
	// // mechanisms for that TokenSource will not be used.
	// Expiry time.Time `json:"expiry,omitempty"`

	// // raw optionally contains extra metadata from the server
	// // when updating a token.
	// raw interface{}

	authHandler := p.OAuthHandlerFunc(cnsiRequest, req, func(skipSSLValidation bool, cnsiGUID, userGUID, client, clientSecret, tokenEndpoint string) (t interfaces.TokenRecord, err error) {
		return p.RefreshDexToken(req.Context(), skipSSLValidation, cnsiGUID, userGUID, client, clientSecret, tokenEndpoint)
	})

	// authHandler := p.OAuthHandlerFunc(cnsiRequest, req, p.RefreshDexToken)

	return p.DoAuthFlowRequest(cnsiRequest, req, authHandler)
}

func (p *portalProxy) RefreshDexToken(ctx context.Context, skipSSLValidation bool, cnsiGUID, userGUID, client, clientSecret, tokenEndpoint string) (t interfaces.TokenRecord, err error) {
	log.Debug("RefreshDexToken")

	// TODO: RC test before committing

	userToken, ok := p.GetCNSITokenRecordWithDisconnected(cnsiGUID, userGUID)
	if !ok {
		return t, fmt.Errorf("Info could not be found for user with GUID %s", userGUID)
	}

	oidcProvider, _ := dex.NewOIDCProvider(ctx, p)

	oathToken := &oauth2.Token{
		AccessToken:  userToken.AuthToken,
		TokenType:    "Bearer",
		RefreshToken: userToken.RefreshToken,
		Expiry:       time.Unix(userToken.TokenExpiry, 0),
	}

	tokenSource := oidcProvider.Config.TokenSource(ctx, oathToken)
	newOathToken, _ := tokenSource.Token() // TODO: err

	// TODO: RC err
	// token, err := oidcProvider.ExchangeWithPKCE(ctx, userToken.RefreshToken, userToken.Metadata) // Metadata contains the code_verifier string

	if err != nil {
		return t, fmt.Errorf("Failed to exchange refresh for token: %+v", err)
	}

	log.Warnf("RefreshDexToken: token: %+v", newOathToken.AccessToken)

	tokenRecord := &interfaces.TokenRecord{
		AuthType:     interfaces.AuthTypeDex,
		AuthToken:    newOathToken.AccessToken,
		RefreshToken: newOathToken.RefreshToken,
		TokenExpiry:  newOathToken.Expiry.Unix(),
		Metadata:     userToken.Metadata, // This will be used for refreshing the token
	}

	// tokenEndpointWithPath := fmt.Sprintf("%s/oauth/token", tokenEndpoint)

	// // Parse out token metadata is there is some, and override some of theser parameters

	// var scopes string

	// log.Info(userToken.Metadata)
	// if len(userToken.Metadata) > 0 {
	// 	metadata := &interfaces.OAuth2Metadata{}
	// 	if err := json.Unmarshal([]byte(userToken.Metadata), metadata); err == nil {
	// 		log.Info(metadata)
	// 		log.Info(metadata.ClientID)
	// 		log.Info(metadata.ClientSecret)

	// 		if len(metadata.ClientID) > 0 {
	// 			client = metadata.ClientID
	// 		}
	// 		if len(metadata.ClientSecret) > 0 {
	// 			clientSecret = metadata.ClientSecret
	// 		}
	// 		if len(metadata.IssuerURL) > 0 {
	// 			tokenEndpoint = metadata.IssuerURL
	// 			tokenEndpointWithPath = fmt.Sprintf("%s/token", tokenEndpoint)
	// 		}
	// 	}
	// }

	// uaaRes, err := p.getUAATokenWithRefreshToken(skipSSLValidation, userToken.RefreshToken, client, clientSecret, tokenEndpointWithPath, scopes)
	// if err != nil {
	// 	return t, fmt.Errorf("Token refresh request failed: %v", err)
	// }

	// u, err := p.GetUserTokenInfo(uaaRes.IDToken)
	// if err != nil {
	// 	return t, fmt.Errorf("Could not get user token info from id token")
	// }

	// u.UserGUID = userGUID

	// tokenRecord := p.InitEndpointTokenRecord(u.TokenExpiry, uaaRes.AccessToken, uaaRes.RefreshToken, userToken.Disconnected)
	// tokenRecord.AuthType = interfaces.AuthTypeOIDC
	// // Copy across the metadata from the original token
	// tokenRecord.Metadata = userToken.Metadata

	err = p.setCNSITokenRecord(cnsiGUID, userGUID, *tokenRecord)
	if err != nil {
		return t, fmt.Errorf("Couldn't save new token: %v", err)
	}

	return *tokenRecord, nil
}
