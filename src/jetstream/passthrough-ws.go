package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/labstack/echo/v4"
	log "github.com/sirupsen/logrus"

	"github.com/epinio/ui-backend/src/jetstream/repository/interfaces"

	httputil2 "github.com/epinio/ui-backend/src/jetstream/websocketproxy/httputil"

	"github.com/epinio/ui-backend/src/jetstream/websocketproxy"
)

// - Enable websocket in reverseproxy https://github.com/golang/go/commit/ee55f0856a3f1fed5d8c15af54c40e4799c2d32f
// - reverseproxy code https://go.dev/src/net/http/httputil/reverseproxy.go?s=575:1776
// - epinio exec reverseproxy https://github.com/epinio/epinio/blob/1b4f8da2aefcb5c22e74d4e6e7b38cdc6728dbc2/internal/cli/server/server.go
// - epinio logger https://github.com/epinio/epinio/blob/77cc8e1b8d566f2c8a187ebc1158a44fe8ddbc81/helpers/kubernetes/tailer/tailer.go
//   - parent app log https://github.com/epinio/epinio/blob/1b4f8da2aefcb5c22e74d4e6e7b38cdc6728dbc2/internal/api/v1/application/logs.go#L116
// - rancher reverseproxy https://github.com/rancher/rancher/blob/5b081792ee67bf17127a465a7353afb3c4fc81d1/pkg/api/steve/clusters/shell.go
// - websocket basics https://developer.mozilla.org/en-US/docs/Web/API/WebSockets_API/Writing_WebSocket_servers
// - epinio cors - https://github.com/epinio/epinio/issues/1234

const (
	// Time allowed to read the next pong message from the peer
	pongWait = 30 * time.Second

	// Send ping messages to peer with this period (must be less than pongWait)
	pingPeriod = (pongWait * 9) / 10
)

func (p *portalProxy) createUrl(c echo.Context) (*url.URL, error) {
	cnsi := c.Param("uuid")

	uri := url.URL{}
	// Ensure we don't escape parameters again
	uri.RawPath = c.Param("*")
	uri.Path, _ = url.PathUnescape(uri.RawPath)

	uri.RawQuery = c.Request().URL.RawQuery

	cnsiRec, err := p.GetCNSIRecord(cnsi) // TODO: RC AUTH - user should be connected in order to use?
	if err != nil {
		return nil, err
	}

	cnsiUri, _ := url.Parse(cnsiRec.DopplerLoggingEndpoint) // TODO: RC handle err
	// The APIEndpoint might have a path already - so join the request URI to it...
	// but ensure we don't escape parameters again
	extraPath := uri.Path
	if len(uri.RawPath) > 0 {
		extraPath = uri.RawPath
	}
	cnsiUri.RawPath = path.Join(uri.Path, extraPath)
	cnsiUri.Path, _ = url.PathUnescape(uri.RawPath)
	cnsiUri.RawQuery = uri.RawQuery

	return cnsiUri, nil
}

// APPROACH 4 `http: proxy error: unsupported protocol scheme "wss"` -------------------------------------------------------------------

func (p *portalProxy) ProxyWebSocketRequest6(c echo.Context) error {
	log.Debug("ProxyWebSocketRequest6")

	cnsiUri, _ := p.createUrl(c) // TODO: RC handle err

	header := getEchoHeaders(c)
	header.Del("Cookie")
	header.Del(APIKeyHeader)

	rp := httputil2.ReverseProxy{
		Director: func(req *http.Request) {
			req.URL = cnsiUri
			// req.Header.Set("Connection", "Upgrade")
			// req.Header.Set("Upgrade", "websocket")

			// req.Host = cnsiUri.Host
			// let kube authentication work
			delete(req.Header, "Cookie")
			delete(req.Header, "Authorization")
		},
		// Transport:     http.RoundTripper,
		FlushInterval: time.Millisecond * 100,
		ErrorHandler: func(rw http.ResponseWriter, req *http.Request, err error) {
			log.Errorf("ERROR: %+v", err)
		},
	}

	rp.ServeHTTP(c.Response().Writer, c.Request())

	return nil
}

// APPROACH 5 - Does nowt (200, nothing epinio) -------------------------------------------------------------------

func (p *portalProxy) ProxyWebSocketRequest5(c echo.Context) error {
	// https://groups.google.com/g/golang-nuts/c/KBx9pDlvFOc?pli=1
	cnsiUri, _ := p.createUrl(c) // TODO: RC handle err

	target := cnsiUri.String()
	w := c.Response().Writer
	r := c.Request()

	// d, err := net.Dial("tcp", target)
	// OR
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true, // TODO: RC
	}
	backendHostPort := cnsiUri.Host
	if !strings.Contains(backendHostPort, ":") {
		backendHostPort = net.JoinHostPort(backendHostPort, "443")
	}
	d, err := tls.DialWithDialer(dialer, "tcp", backendHostPort, tlsConfig)

	if err != nil {
		http.Error(w, "Error contacting backend server.", 500)
		log.Printf("Error dialing websocket backend %s: %v", target, err)
		return err
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Not a hijacker?", 500)
		return err
	}
	nc, _, err := hj.Hijack()
	if err != nil {
		log.Printf("Hijack error: %v", err)
		return err
	}
	defer nc.Close()
	defer d.Close()

	err = r.Write(d)
	if err != nil {
		log.Printf("Error copying request to target: %v", err)
		return err
	}

	errc := make(chan error, 2)
	cp := func(dst io.Writer, src io.Reader) {
		_, err := io.Copy(dst, src)
		errc <- err
	}
	go cp(d, nc)
	go cp(nc, d)
	<-errc

	return nil
}

// APPROACH 4 `http: proxy error: unsupported protocol scheme "wss"` -------------------------------------------------------------------

func serveReverseProxy(target string, res http.ResponseWriter, req *http.Request) {
	// parse the url
	url, _ := url.Parse(target)

	// create the reverse proxy

	proxy := httputil.NewSingleHostReverseProxy(url)

	tlsConfig := &tls.Config{
		InsecureSkipVerify: true, // TODO: RC
	}
	t := &http.Transport{TLSClientConfig: tlsConfig}
	proxy.Transport = t

	// Update the headers to allow for SSL redirection
	req.URL.Host = url.Host
	req.URL.Scheme = url.Scheme
	req.Header.Set("X-Forwarded-Host", req.Header.Get("Host"))
	req.Host = url.Host

	// Note that ServeHttp is non blocking and uses a go routine under the hood
	proxy.ServeHTTP(res, req)
}

func (p *portalProxy) ProxyWebSocketRequest4(c echo.Context) error {
	log.Debug("ProxyWebSocketRequest2")

	cnsiUri, _ := p.createUrl(c) // TODO: RC handle err

	header := getEchoHeaders(c)
	header.Del("Cookie")
	header.Del(APIKeyHeader)

	serveReverseProxy(cnsiUri.String(), c.Response().Writer, c.Request())

	return nil
}

// APPROACH 3 http: proxy error: unsupported protocol scheme "wss" -------------------------------------------------------------------

func (p *portalProxy) ProxyWebSocketRequest3(c echo.Context) error {
	log.Debug("ProxyWebSocketRequest3")

	cnsiUri, _ := p.createUrl(c) // TODO: RC handle err

	header := getEchoHeaders(c)
	header.Del("Cookie")
	header.Del(APIKeyHeader)

	reverseProxy := httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.URL = cnsiUri

			log.Errorf("!!!!!: req.Url type: %T", req.URL)
			log.Errorf("!!!!!: req.URL.Scheme: %+v", req.URL.Scheme)
			log.Errorf("!!!!!: req.URL.Host: %+v", req.URL.Host)
			log.Errorf("!!!!!: req.URL: %+v", req.URL)
			// req.Header.Set("Connection", "Upgrade")
			// req.Header.Set("Upgrade", "websocket")

			if _, ok := req.Header["User-Agent"]; !ok {
				// explicitly disable User-Agent so it's not set to default value
				req.Header.Set("User-Agent", "")
			}
			req.Header.Set("X-Forwarded-Host", req.Header.Get("Host"))

			// req.URL.Scheme = "https"
			req.Host = cnsiUri.Host
			// let kube authentication work
			delete(req.Header, "Cookie")
			delete(req.Header, "Authorization")
		},
		// Transport:     http.RoundTripper,
		FlushInterval: -1,
		// ErrorHandler: func(rw http.ResponseWriter, req *http.Request, err error) {
		// 	log.Warnf("ErrorHandler: %+v", err)
		// 	log.Warnf("ErrorHandler: req: %+v", req)
		// 	log.Warnf("ErrorHandler: rw: %+v", rw)
		// },
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
		// Transport: spdy.NewRoundTripperWithConfig(spdy.RoundTripperConfig{
		// 	TLS:                      http.DefaultTransport.(*http.Transport).TLSClientConfig, // See `ExtendLocalTrust`
		// 	FollowRedirects:          true,
		// 	RequireSameHostRedirects: false,
		// 	PingPeriod:               time.Second * 5,
		// }),
		// ModifyResponse: func(res *http.Response) error {
		// 	log.Warnf("ModifyResponse: Response: %+v", res)

		// 	b, err := io.ReadAll(res.Body)
		// 	// b, err := ioutil.ReadAll(resp.Body)  Go.1.15 and earlier
		// 	if err != nil {
		// 		log.Fatalln(err)
		// 	}
		// 	log.Warnf("ModifyResponse: Response Body: %+v", string(b))

		// 	return nil
		// },
	}

	reverseProxy.ServeHTTP(c.Response().Writer, c.Request())

	return nil
}

// APPROACH 2 Read Msg: -1,[]websocket: close 1006 (abnormal closure): unexpected EOF -------------------------------------------------------------------

func (p *portalProxy) ProxyWebSocketRequest2(c echo.Context) error {
	// https://github.com/koding/websocketproxy
	log.Debug("ProxyWebSocketRequest2")

	cnsiUri, _ := p.createUrl(c) // TODO: RC handle err

	header := getEchoHeaders(c)
	header.Del("Cookie")
	header.Del(APIKeyHeader)

	websocketproxy.NewProxy(cnsiUri).ServeHTTP(c.Response().Writer, c.Request()) // TODO: RC is this the issue?

	return nil
}

// Allow connections from any Origin
// var upgrader = websocket.Upgrader{
// 	CheckOrigin: func(r *http.Request) bool { return true }, // TODO: RC FIX!
// }

// APPROACH 1 -------------------------------------------------------------------

func (p *portalProxy) ProxyWebSocketRequest(c echo.Context) error {
	log.Debug("ProxyWebSocketRequest")

	cnsiUri, _ := p.createUrl(c) // TODO: RC handle err

	// cnsi := c.Param("uuid")

	// uri := url.URL{}
	// // Ensure we don't escape parameters again
	// uri.RawPath = c.Param("*")
	// uri.Path, _ = url.PathUnescape(uri.RawPath)

	// uri.RawQuery = c.Request().URL.RawQuery

	header := getEchoHeaders(c)
	header.Del("Cookie")
	header.Del(APIKeyHeader)

	socketProxy(c.Response().Writer, c.Request(), cnsiUri)

	return nil
}

func newSingleHostReverseProxy(cnsiRequest interfaces.CNSIRequest) *httputil.ReverseProxy {
	// targetQuery := cnsiRequest.URL.RawQuery
	director := func(req *http.Request) {
		req.URL = cnsiRequest.URL
		req.Header = cnsiRequest.Header
		// req.URL.Scheme =  cnsiRequest.URL.Scheme
		// req.URL.Host =  cnsiRequest.URL.Host
		// req.URL.Path, req.URL.RawPath = joinURLPath(target, req.URL)
		// if targetQuery == "" || req.URL.RawQuery == "" {
		// 	req.URL.RawQuery = targetQuery + req.URL.RawQuery
		// } else {
		// 	req.URL.RawQuery = targetQuery + "&" + req.URL.RawQuery
		// }
		// if _, ok := req.Header["User-Agent"]; !ok {
		// 	// explicitly disable User-Agent so it's not set to default value
		// 	req.Header.Set("User-Agent", "")
		// }
	}
	return &httputil.ReverseProxy{Director: director}
}

func socketProxy(w http.ResponseWriter, r *http.Request, cnsiUri *url.URL) {
	log.Debug("socketProxy")
	// u, err := url.Parse(target)
	// rp := newSingleHostReverseProxy(cnsiRequest)

	hj, _ := w.(http.Hijacker) //isHJ
	// if r.Header.Get("Upgrade") == "websocket" && isHJ {
	log.Debug("asdasdsadasdasdsadsocketProxy")
	c, br, err := hj.Hijack()
	if err != nil {
		log.Printf("websocket websocket hijack: %v", err)
		http.Error(w, err.Error(), 500)
		return
	}
	defer c.Close()

	dialer := &net.Dialer{Timeout: 10 * time.Second}
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true, // TODO: RC
	}

	var be net.Conn
	if len(cnsiUri.Port()) == 0 {
		backendHostPort := cnsiUri.Host
		if !strings.Contains(backendHostPort, ":") {
			backendHostPort = net.JoinHostPort(backendHostPort, "443")
		}
		be, err = tls.DialWithDialer(dialer, "tcp", backendHostPort, tlsConfig)
	} else {
		be, err = tls.DialWithDialer(dialer, "tcp", cnsiUri.Host, tlsConfig)
	}
	if err != nil {
		log.Printf("websocket Dial: %v", err)
		http.Error(w, err.Error(), 500)
		return
	}
	defer be.Close()
	if err := r.Write(be); err != nil {
		log.Printf("websocket backend write request: %v", err)
		http.Error(w, err.Error(), 500)
		return
	}
	errc := make(chan error, 1)
	go func() {
		n, err := io.Copy(be, br) // backend <- buffered reader
		if err != nil {
			err = fmt.Errorf("websocket: to copy backend from buffered reader: %v, %v", n, err)
		}
		errc <- err
	}()
	go func() {
		n, err := io.Copy(c, be) // raw conn <- backend
		if err != nil {
			err = fmt.Errorf("websocket: to raw conn from backend: %v, %v", n, err)
		}
		errc <- err
	}()
	if err := <-errc; err != nil {
		log.Print(err)
	}
	return
	// }
	// rp.ServeHTTP(w, r)
}

// func (p *portalProxy) commonStreamHandler(echoContext echo.Context, bespokeStreamHandler func(echo.Context, *AuthorizedConsumer, *websocket.Conn) error) error {
// 	ac, err := p.openNoaaConsumer(echoContext)
// 	if err != nil {
// 		return err
// 	}
// 	defer ac.consumer.Close()

// 	clientWebSocket, pingTicker, err := interfaces.UpgradeToWebSocket(echoContext)
// 	if err != nil {
// 		return err
// 	}
// 	defer clientWebSocket.Close()
// 	defer pingTicker.Stop()

// 	if err := bespokeStreamHandler(echoContext, ac, clientWebSocket); err != nil {
// 		return err
// 	}

// 	// This blocks until the WebSocket is closed
// 	drainClientMessages(clientWebSocket)
// 	return nil
// }

// type AuthorizedConsumer struct {
// 	consumer     *consumer.Consumer
// 	authToken    string
// 	refreshToken func() error
// }

// // Refresh the Authorization token if needed and create a new Noaa consumer
// func (p *portalProxy) openNoaaConsumer(echoContext echo.Context) (*AuthorizedConsumer, error) {

// 	ac := &AuthorizedConsumer{}

// 	// Get the CNSI and app IDs from route parameters
// 	cnsiGUID := echoContext.Param("uuid")
// 	userGUID := echoContext.Get("user_id").(string)

// 	// Extract the Doppler endpoint from the CNSI record
// 	cnsiRecord, err := p.GetCNSIRecord(cnsiGUID)
// 	if err != nil {
// 		return nil, fmt.Errorf("Failed to get record for CNSI %s: [%v]", cnsiGUID, err)
// 	}

// 	ac.refreshToken = func() error {
// 		newTokenRecord, err := p.RefreshOAuthToken(cnsiRecord.SkipSSLValidation, cnsiGUID, userGUID, cnsiRecord.ClientId, cnsiRecord.ClientSecret, cnsiRecord.TokenEndpoint)
// 		if err != nil {
// 			msg := fmt.Sprintf("Error refreshing token for CNSI %s : [%v]", cnsiGUID, err)
// 			return echo.NewHTTPError(http.StatusUnauthorized, msg)
// 		}
// 		ac.authToken = "bearer " + newTokenRecord.AuthToken
// 		return nil
// 	}

// 	dopplerAddress := cnsiRecord.DopplerLoggingEndpoint // TODO: RC setup
// 	log.Debugf("CNSI record Obtained! Using Doppler Logging Endpoint: %s", dopplerAddress)

// 	// Get the auth token for the CNSI from the DB, refresh it if it's expired
// 	if tokenRecord, ok := p.GetCNSITokenRecord(cnsiGUID, userGUID); ok && !tokenRecord.Disconnected {
// 		ac.authToken = "bearer " + tokenRecord.AuthToken
// 		expTime := time.Unix(tokenRecord.TokenExpiry, 0)
// 		if expTime.Before(time.Now()) {
// 			log.Debug("Token obtained has expired, refreshing!")
// 			if err = ac.refreshToken(); err != nil {
// 				return nil, err
// 			}
// 		}
// 	} else {
// 		return nil, fmt.Errorf("Error getting token for user %s on CNSI %s", userGUID, cnsiGUID)
// 	}

// 	// Open a Noaa consumer to the doppler endpoint
// 	log.Debugf("Creating Noaa consumer for Doppler endpoint %s", dopplerAddress)
// 	// TODO: RC InsecureSkipVerify
// 	ac.consumer = consumer.New(dopplerAddress, &tls.Config{InsecureSkipVerify: true}, http.ProxyFromEnvironment)

// 	return ac, nil
// }

// // Attempts to get the recent logs, if we get an unauthorized error we will refresh the auth token and retry once
// func getRecentLogs(ac *AuthorizedConsumer, cnsiGUID, appGUID string) ([]*events.LogMessage, error) {
// 	log.Debug("getRecentLogs")
// 	messages, err := ac.consumer.RecentLogs(appGUID, ac.authToken)
// 	if err != nil {
// 		errorPattern := "Failed to get recent messages for App %s on CNSI %s [%v]"
// 		if _, ok := err.(*noaa_errors.UnauthorizedError); ok {
// 			// If unauthorized, we may need to refresh our Auth token
// 			// Note: annoyingly, older versions of CF also send back "401 - Unauthorized" when the app doesn't exist...
// 			// This means we sometimes end up here even when our token is legit
// 			if err := ac.refreshToken(); err != nil {
// 				return nil, fmt.Errorf(errorPattern, appGUID, cnsiGUID, err)
// 			}
// 			messages, err = ac.consumer.RecentLogs(appGUID, ac.authToken)
// 			if err != nil {
// 				msg := fmt.Sprintf(errorPattern, appGUID, cnsiGUID, err)
// 				return nil, echo.NewHTTPError(http.StatusUnauthorized, msg)
// 			}
// 		} else {
// 			return nil, fmt.Errorf(errorPattern, appGUID, cnsiGUID, err)
// 		}
// 	}
// 	return messages, nil
// }

// func drainErrors(errorChan <-chan error) {
// 	for err := range errorChan {
// 		// Note: we receive a nil error before the channel is closed so check here...
// 		if err != nil {
// 			log.Errorf("Received error from Doppler %v", err.Error())
// 		}
// 	}
// }

// func drainLogMessages(msgChan <-chan *events.LogMessage, callback func(msg *events.LogMessage)) {
// 	for msg := range msgChan {
// 		callback(msg)
// 	}
// }

// func drainFirehoseEvents(eventChan <-chan *events.Envelope, callback func(msg *events.Envelope)) {
// 	for event := range eventChan {
// 		callback(event)
// 	}
// }

// // Drain and discard incoming messages from the WebSocket client, effectively making our WebSocket read-only
// func drainClientMessages(clientWebSocket *websocket.Conn) {
// 	for {
// 		_, _, err := clientWebSocket.ReadMessage()
// 		if err != nil {
// 			// We get here when the client (browser) disconnects
// 			break
// 		}
// 	}
// }

// func appStreamHandler(echoContext echo.Context, ac *AuthorizedConsumer, clientWebSocket *websocket.Conn) error {
// 	// Get the CNSI and app IDs from route parameters
// 	cnsiGUID := echoContext.Param("cnsiGuid")
// 	appGUID := echoContext.Param("appGuid")

// 	log.Infof("Received request for log stream for App ID: %s - in CNSI: %s", appGUID, cnsiGUID)

// 	messages, err := getRecentLogs(ac, cnsiGUID, appGUID)
// 	if err != nil {
// 		return err
// 	}
// 	// Reusable closure to pump messages from Noaa to the client WebSocket
// 	// N.B. We convert protobuf messages to JSON for ease of use in the frontend
// 	relayLogMsg := func(msg *events.LogMessage) {
// 		if jsonMsg, err := json.Marshal(msg); err != nil {
// 			log.Errorf("Received unparsable message from Doppler %v, %v", jsonMsg, err)
// 		} else {
// 			err := clientWebSocket.WriteMessage(websocket.TextMessage, jsonMsg)
// 			if err != nil {
// 				log.Errorf("Error writing data to WebSocket, %v", err)
// 			}
// 		}
// 	}

// 	// Send the recent messages, sorted in Chronological order
// 	for _, msg := range noaa.SortRecent(messages) {
// 		relayLogMsg(msg)
// 	}

// 	msgChan, errorChan := ac.consumer.TailingLogs(appGUID, ac.authToken)

// 	// Process the app stream
// 	go drainErrors(errorChan)
// 	go drainLogMessages(msgChan, relayLogMsg)

// 	log.Infof("Now streaming log for App ID: %s - on CNSI: %s", appGUID, cnsiGUID)
// 	return nil
// }

// func firehoseStreamHandler(echoContext echo.Context, ac *AuthorizedConsumer, clientWebSocket *websocket.Conn) error {
// 	log.Debug("firehose")

// 	// Get the CNSI and app IDs from route parameters
// 	cnsiGUID := echoContext.Param("uuid")

// 	log.Infof("Received request for Firehose stream for CNSI: %s", cnsiGUID)

// 	userGUID := echoContext.Get("user_id").(string)
// 	firehoseSubscriptionId := userGUID + "@" + strconv.FormatInt(time.Now().UnixNano(), 10)
// 	log.Debugf("Connecting the Firehose with subscription ID: %s", firehoseSubscriptionId)

// 	eventChan, errorChan := ac.consumer.Firehose(firehoseSubscriptionId, ac.authToken)

// 	// Process the app stream
// 	go drainErrors(errorChan)
// 	go drainFirehoseEvents(eventChan, func(msg *events.Envelope) {
// 		if jsonMsg, err := json.Marshal(msg); err != nil {
// 			log.Errorf("Received unparsable message from Doppler %v, %v", jsonMsg, err)
// 		} else {
// 			err := clientWebSocket.WriteMessage(websocket.TextMessage, jsonMsg)
// 			if err != nil {
// 				log.Errorf("Error writing data to WebSocket, %v", err)
// 			}
// 		}
// 	})

// 	log.Infof("Firehose connected and streaming for CNSI: %s - subscription ID: %s", cnsiGUID, firehoseSubscriptionId)
// 	return nil
// }

// func appFirehoseStreamHandler(echoContext echo.Context, ac *AuthorizedConsumer, clientWebSocket *websocket.Conn) error {
// 	log.Debug("appFirehoseStreamHandler")

// 	// Get the CNSI and app IDs from route parameters
// 	cnsiGUID := echoContext.Param("cnsiGuid")
// 	appGUID := echoContext.Param("appGuid")

// 	log.Infof("Received request for log stream for App ID: %s - in CNSI: %s", appGUID, cnsiGUID)

// 	msgChan, errorChan := ac.consumer.Stream(appGUID, ac.authToken)

// 	// Process the app stream
// 	go drainErrors(errorChan)
// 	go drainFirehoseEvents(msgChan, func(msg *events.Envelope) {
// 		if jsonMsg, err := json.Marshal(msg); err != nil {
// 			log.Errorf("Received unparsable message from Doppler %v, %v", jsonMsg, err)
// 		} else {
// 			err := clientWebSocket.WriteMessage(websocket.TextMessage, jsonMsg)
// 			if err != nil {
// 				log.Errorf("Error writing data to WebSocket, %v", err)
// 			}
// 		}
// 	})

// 	log.Infof("Now streaming for App ID: %s - on CNSI: %s", appGUID, cnsiGUID)
// 	return nil
// }
