package main

import (
	"net/http"

	"github.com/everettcaleb/go-proxyproto"
)

func main() {
	proxyproto.ListenAndServeHTTP(":8080", echoProxyProto())
}

func echoProxyProto() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(200)
		w.Write([]byte(r.RemoteAddr + "\n\n"))
	}
}
