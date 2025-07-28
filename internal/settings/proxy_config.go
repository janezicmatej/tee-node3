package settings

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/flare-foundation/go-flare-common/pkg/logger"
	"github.com/flare-foundation/tee-node/pkg/types"
)

var ProxyUrl ProxyUrlMutex

type ProxyUrlMutex struct {
	Url string

	sync.RWMutex
}

func ProxyUrlConfigServer() {
	addr := fmt.Sprintf(":%d", ProxyConfigureServerPort)

	server := &http.Server{
		Addr: addr,
	}

	mux := http.NewServeMux()
	server.Handler = mux
	mux.HandleFunc("POST /configure", setProxyUrl)

	for {
		err := server.ListenAndServe()
		if err != nil {
			logger.Errorf("error serving proxy url config: %v", err)
		}

		time.Sleep(time.Second)
	}
}

func setProxyUrl(w http.ResponseWriter, r *http.Request) {
	var request types.ConfigureProxyUrlRequest
	err := json.NewDecoder(r.Body).Decode(&request)
	if err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	ProxyUrl.Lock()
	defer ProxyUrl.Unlock()

	ProxyUrl.Url = request.Url
}
