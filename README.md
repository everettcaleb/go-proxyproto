# go-proxyproto

[![Go Report Card](https://goreportcard.com/badge/github.com/everettcaleb/go-proxyproto?style=flat-square)](https://goreportcard.com/report/github.com/everettcaleb/go-proxyproto)
[![Go Doc](https://img.shields.io/badge/godoc-reference-blue.svg?style=flat-square)](http://godoc.org/github.com/everettcaleb/go-proxyproto)
[![Release](https://img.shields.io/github/release/everettcaleb/go-proxyproto.svg?style=flat-square)](https://github.com/everettcaleb/go-proxyproto/releases/latest)

Proxy Protocol Library with support for parsing v1, v2, and SSL TLV extensions. You can find the spec for Proxy Protocol v1 and v2 here: https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt.

## Using this Library
There's an example in [cmd/http-example](cmd/http-example) showing how to create an HTTP server that consumes Proxy Protocol. Here's what the code looks like:

```go
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
```

The helpers available are:

- `Listen` (equivalent to `net.Listen`)
- `ListenTLS` (equivalent to `tls.Listen`)
- `ListenAndServeHTTP` (equivalent to `http.ListenAndServe`)
- `ListenAndServeHTTPS` (roughly equivalent to `http.ListenAndServeTLS`)

## TODO
- Add tests for Conn_Read
- Add code to automatically validate CRC32C TLV if present
- Add code to allow getting connection/proxy data from http.Request (not currently possible)
- Add code for generating Proxy Protocol v1/v2 payloads so library can be used to implement a reverse proxy
