// TODO: RC REMOVE FILE
package epinio // TODO: RC make epinioproxy

import (
	"bytes"
	// "encoding/json"
	"errors"
	// "fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"path"
	"strings"

	"github.com/epinio/ui-backend/src/jetstream/repository/interfaces"

	"github.com/labstack/echo/v4"
	log "github.com/sirupsen/logrus"
)

const (
	longRunningTimeoutHeader = "x-cap-long-running"
	noTokenHeader            = "x-cap-no-token"
)

func getEchoHeaders(c echo.Context) http.Header {
	log.Debug("getEchoHeaders")
	h := make(http.Header)
	originalHeader := c.Request().Header
	for k, v := range originalHeader {
		if k == "Cookie" {
			continue
		}
		vCopy := make([]string, len(v))
		copy(vCopy, v)
		h[k] = vCopy
	}

	return h
}

func getPortalUserGUID(c echo.Context) (string, error) {
	log.Debug("getPortalUserGUID")
	portalUserGUIDIntf := c.Get("user_id")
	if portalUserGUIDIntf == nil {
		return "", errors.New("Corrupted session")
	}
	return portalUserGUIDIntf.(string), nil
}

func getRequestParts(c echo.Context) (*http.Request, []byte, error) {
	log.Debug("getRequestParts")
	var body []byte
	var err error
	req := c.Request()
	if bodyReader := req.Body; bodyReader != nil {
		if body, err = ioutil.ReadAll(bodyReader); err != nil {
			return nil, nil, errors.New("Failed to read request body")
		}
	}
	return req, body, nil
}

func (epinio *Epinio) buildCNSIRequest(cnsiGUID string, userGUID string, method string, uri *url.URL, body []byte, header http.Header) (interfaces.CNSIRequest, error) {
	log.Debug("buildCNSIRequest")
	cnsiRequest := interfaces.CNSIRequest{
		GUID:     cnsiGUID,
		UserGUID: userGUID,

		Method: method,
		Body:   body,
		Header: header,
	}

	// cnsiRec, err := p.GetCNSIRecord(cnsiGUID)
	// if err != nil {
	// 	return cnsiRequest, err
	// }

	// cnsiRequest.URL = new(url.URL)
	cnsiRequest.URL, _ = url.Parse("https://epinio.192.168.16.22222.nip.io")  // TODO: RC *cnsiRec.APIEndpoint
	// TODO: RC handle err

	// The APIEndpoint might have a path already - so join the request URI to it...
	// but ensure we don't escape parameters again
	extraPath := uri.Path
	if len(uri.RawPath) > 0 {
		extraPath = uri.RawPath
	}
	cnsiRequest.URL.RawPath = path.Join(cnsiRequest.URL.Path, extraPath)
	cnsiRequest.URL.Path, _ = url.PathUnescape(cnsiRequest.URL.RawPath)

	cnsiRequest.URL.RawQuery = uri.RawQuery

	return cnsiRequest, nil
}

func fwdCNSIStandardHeaders(cnsiRequest *interfaces.CNSIRequest, req *http.Request) {
	log.Debug("fwdCNSIStandardHeaders")
	for k, v := range cnsiRequest.Header {
		switch {
		// Skip these
		//  - "Referer" causes CF to fail with a 403
		//  - "Connection", "X-Cap-*" and "Cookie" are consumed by us
		//  - "Accept-Encoding" must be excluded otherwise the transport will expect us to handle the encoding/compression
		//  - X-Forwarded-* headers - these will confuse Cloud Foundry in some cases (e.g. load balancers)
		case k == "Connection", k == "Cookie", k == "Referer", k == "Accept-Encoding",
			strings.HasPrefix(strings.ToLower(k), "x-cap-"),
			strings.HasPrefix(strings.ToLower(k), "x-forwarded-"):

		// Forwarding everything else
		default:
			req.Header[k] = v
		}
	}
}


func (epinio *Epinio) EpinioProxyRequest(c echo.Context) error {
	log.Debug("EpinioProxyRequest")

	cnsi := "N/A" // TODO: RC c.Param("uuid")

	uri := url.URL{}
	// Ensure we don't escape parameters again
	uri.RawPath = c.Param("*")
	uri.Path, _ = url.PathUnescape(uri.RawPath)

	uri.RawQuery = c.Request().URL.RawQuery

	header := getEchoHeaders(c)
	header.Del("Cookie")
	header.Del("Authentication") // TODO: RC `APIKeyHeader``

	portalUserGUID, err := getPortalUserGUID(c)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	req, body, err := getRequestParts(c)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	done := make(chan *interfaces.CNSIRequest)
	cnsiRequest, buildErr := epinio.buildCNSIRequest(cnsi, portalUserGUID, req.Method, &uri, body, header)
	if buildErr != nil {
		return echo.NewHTTPError(http.StatusBadRequest, buildErr.Error())
	}

	longRunning := "true" == c.Request().Header.Get(longRunningTimeoutHeader)
	noToken := "true" == c.Request().Header.Get(noTokenHeader)

	cnsiRequest.LongRunning = longRunning
	if noToken {
		// Fake a token record with no authentication
		cnsiRequest.Token = &interfaces.TokenRecord{
			AuthType: interfaces.AuthConnectTypeNone,
		}
	}

	go epinio.doRequest(&cnsiRequest, done)
	res := <-done

	// FIXME: cnsiRequest.Status info is lost for failures, only get a status code
	c.Response().WriteHeader(res.StatusCode)

	// we don't care if this fails
	_, writeErr := c.Response().Write(res.Response)
	if writeErr != nil { // TODO: RC eh??
		log.Errorf("Failed to write passthrough response %v", err)
	}

	return nil
}


func (epinio *Epinio) doRequest(cnsiRequest *interfaces.CNSIRequest, done chan<- *interfaces.CNSIRequest) {
	log.Debugf("doRequest for URL: %s", cnsiRequest.URL.String())
	var body io.Reader
	var res *http.Response
	var req *http.Request
	var err error

	if len(cnsiRequest.Body) > 0 {
		body = bytes.NewReader(cnsiRequest.Body)
	}

	proxyURL := cnsiRequest.URL.String()

	req, err = http.NewRequest(cnsiRequest.Method, proxyURL, body)
	if err != nil {
		cnsiRequest.Error = err
		if done != nil {
			done <- cnsiRequest
		}
		return
	}

	var tokenRec *interfaces.TokenRecord
	if cnsiRequest.Token != nil {
		tokenRec = cnsiRequest.Token
	} else {
		tokenRec = &interfaces.TokenRecord{
			AuthToken:     "asdsad", // TODO: RC
			AuthType:       interfaces.AuthTypeBearer,
		}

		// TokenGUID:     "",
		// AuthToken:     "",
		// RefreshToken:   "",
		// TokenExpiry:    1,
		// Disconnected:   false,
		// AuthType:       interfaces.AuthTypeBearer,
		// Metadata:       "",
		// SystemShared:   false,
		// LinkedGUID:     "",
		// Certificate:    "",
		// CertificateKey: "",


		// get a cnsi token record and a cnsi record
		// tokenRec, _, err = p.getCNSIRequestRecords(cnsiRequest)
		// if err != nil {
		// 	cnsiRequest.Error = err
		// 	if done != nil {
		// 		cnsiRequest.StatusCode = 400
		// 		cnsiRequest.Status = "Unable to retrieve CNSI token record"
		// 		done <- cnsiRequest
		// 	}
		// 	return
		// }
	}

	// Copy original headers through, except custom portal-proxy Headers
	fwdCNSIStandardHeaders(cnsiRequest, req)

	// If this is a long running request, add a header which we can use at request time to change the timeout
	if cnsiRequest.LongRunning {
		req.Header.Set(longRunningTimeoutHeader, "true")
	}

	log.Warn("my passthrough: 1")
	// Find the auth provider for the auth type - default ot oauthflow
	authHandler := epinio.portalProxy.GetAuthProvider(tokenRec.AuthType)
	if authHandler.Handler != nil {
		log.Warn("my passthrough: 2")
		res, err = authHandler.Handler(cnsiRequest, req)
	} else {
		log.Warn("my passthrough: 3")
		res, err = epinio.portalProxy.DoOAuthFlowRequest(cnsiRequest, req)
	}
	log.Warn("my passthrough: 4")
	if err != nil {
		cnsiRequest.StatusCode = 500
		cnsiRequest.Status = "Error proxing request"
		cnsiRequest.Response = []byte(err.Error())
		cnsiRequest.Error = err
	} else if res.Body != nil {
		cnsiRequest.StatusCode = res.StatusCode
		cnsiRequest.Status = res.Status
		cnsiRequest.Response, cnsiRequest.Error = ioutil.ReadAll(res.Body)
		defer res.Body.Close()
	}

	// If Status Code >=400, log this as a warning
	if cnsiRequest.StatusCode >= 400 {
		var contentType = "Unknown"
		var contentLength int64 = -1
		if res != nil {
			contentType = res.Header.Get("Content-Type")
			contentLength = res.ContentLength
		}
		log.Warnf("Passthrough response: URL: %s, Status Code: %d, Status: %s, Content Type: %s, Length: %d",
			cnsiRequest.URL.String(), cnsiRequest.StatusCode, cnsiRequest.Status, contentType, contentLength)
		log.Warn(string(cnsiRequest.Response))
	}

	if done != nil {
		done <- cnsiRequest
	}
}
