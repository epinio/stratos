package main

import (
	"crypto/tls"
	"net/http"
	"net/url"
	"path"

	"github.com/gorilla/websocket"
	"github.com/labstack/echo/v4"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

func (p *portalProxy) ProxyWebSocketRequest(c echo.Context) error {
	cnsiUri, skipSllValidation, err := p.createUrl(c)
	if err != nil {
		return errors.Wrap(err, "error creating CNSI url")
	}

	var upgrader = websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
	incomingWebSocketConn, err := upgrader.Upgrade(c.Response().Writer, c.Request(), nil)
	if err != nil {
		return errors.Wrap(err, "error upgrading incoming connection")
	}

	websocket.DefaultDialer.TLSClientConfig = &tls.Config{InsecureSkipVerify: skipSllValidation}
	epinioWebSocketConn, _, err := websocket.DefaultDialer.Dial(cnsiUri.String(), http.Header{})
	if err != nil {
		return errors.Wrap(err, "error opening websocket connection to Epinio")
	}

	errChan := make(chan error)

	// read client messages
	go func() {
		for {
			// we don't care about the messages, we just want to close the connection properly
			_, _, err := incomingWebSocketConn.ReadMessage()
			if err != nil {
				log.Debug("error reading message from incomingWebSocketConn ", err)
				epinioWebSocketConn.Close()
				incomingWebSocketConn.Close()
				break
			}
		}
		log.Debug("closing incomingWebSocketConn")
	}()

	// read Epinio logs and forward them to client
	go func() {
		for {
			// read logs from Epinio
			_, message, err := epinioWebSocketConn.ReadMessage()
			if err != nil {
				log.Debug("error reading message from epinioWebSocketConn ", err)
				epinioWebSocketConn.Close()
				incomingWebSocketConn.Close()
				break
			}

			err = incomingWebSocketConn.WriteMessage(websocket.TextMessage, message)
			if err != nil {
				log.Debug("error writing message to incomingWebSocketConn ", err)
				epinioWebSocketConn.Close()
				incomingWebSocketConn.Close()
				break
			}
		}
		log.Debug("closing epinioWebSocketConn")
	}()

	return <-errChan
}

func (p *portalProxy) createUrl(c echo.Context) (*url.URL, bool, error) {
	var err error
	uri := url.URL{}

	cnsi := c.Param("uuid")

	// Ensure we don't escape parameters again
	uri.RawPath = c.Param("*")
	uri.Path, err = url.PathUnescape(uri.RawPath)
	if err != nil {
		return nil, false, errors.Wrap(err, "error unescaping path")
	}

	uri.RawQuery = c.Request().URL.RawQuery

	cnsiRec, err := p.GetCNSIRecord(cnsi) // TODO: RC AUTH - user should be connected in order to use?
	if err != nil {
		return nil, false, errors.Wrap(err, "error getting CNSI record")
	}

	cnsiUri, _ := url.Parse(cnsiRec.DopplerLoggingEndpoint)
	if err != nil {
		return nil, false, errors.Wrap(err, "error parsing Doppler logging endpoint")
	}

	// The APIEndpoint might have a path already - so join the request URI to it...
	// but ensure we don't escape parameters again
	extraPath := uri.Path
	if len(uri.RawPath) > 0 {
		extraPath = uri.RawPath
	}
	cnsiUri.RawPath = path.Join(uri.Path, extraPath)
	cnsiUri.RawQuery = uri.RawQuery

	cnsiUri.Path, err = url.PathUnescape(uri.RawPath)
	if err != nil {
		return nil, false, errors.Wrap(err, "error unescaping path again")
	}

	return cnsiUri, cnsiRec.SkipSSLValidation, nil
}
