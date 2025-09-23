package settings

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sync"

	"github.com/flare-foundation/tee-node/pkg/types"
)

type ProxyURLMutex struct {
	URL string

	sync.RWMutex
}

type ProxyConfigureServer struct {
	server *http.Server

	ProxyUrl *ProxyURLMutex
}

// NewProxyConfigServer creates an HTTP server that accepts proxy configuration
// requests on the provided port and exposes the configured URL via ProxyUrl.
func NewProxyConfigServer(setProxyPort int) *ProxyConfigureServer {
	proxyUrl := &ProxyURLMutex{}
	proxyUrl.setProxyUrlFromEnv()

	addr := fmt.Sprintf(":%d", setProxyPort)
	server := &http.Server{
		Addr: addr,
	}
	mux := http.NewServeMux()
	server.Handler = mux
	mux.HandleFunc("POST /configure", proxyUrl.setProxyURL)

	pc := ProxyConfigureServer{
		server:   server,
		ProxyUrl: proxyUrl,
	}

	return &pc
}

// setProxyUrlFromEnv sets the proxy url from the environment variable PROXY_URL if it was not already set.
func (proxyUrl *ProxyURLMutex) setProxyUrlFromEnv() {
	proxyUrl.Lock()
	defer proxyUrl.Unlock()

	if proxyUrl.URL != "" {
		return
	}

	initialProxyUrl := os.Getenv("PROXY_URL")
	if initialProxyUrl != "" {
		proxyUrl.URL = initialProxyUrl
	}
}

// Serve starts the proxy configuration server and blocks until it stops.
func (pc *ProxyConfigureServer) Serve() error {
	return pc.server.ListenAndServe()
}

// Close gracefully shuts down the proxy configuration server.
func (pc *ProxyConfigureServer) Close(ctx context.Context) error {
	return pc.server.Shutdown(ctx)
}

func (proxyUrl *ProxyURLMutex) setProxyURL(w http.ResponseWriter, r *http.Request) {
	var request types.ConfigureProxyUrlRequest
	err := json.NewDecoder(r.Body).Decode(&request)
	if err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	proxyUrl.Lock()
	defer proxyUrl.Unlock()

	proxyUrl.URL = request.Url
}
