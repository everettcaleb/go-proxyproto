package proxyproto

import (
	"crypto/tls"
	"net"
	"net/http"
)

func Listen(network, addr string) (net.Listener, error) {
	lis, err := net.Listen(network, addr)
	if err != nil {
		return nil, err
	}
	return WrapListener(lis), nil
}

func ListenTLS(network, addr string, config *tls.Config) (net.Listener, error) {
	lis, err := tls.Listen(network, addr, config)
	if err != nil {
		return nil, err
	}
	return WrapListener(lis), nil
}

func ListenAndServeHTTP(addr string, handler http.Handler) error {
	lis, err := Listen("tcp", addr)
	if err != nil {
		return err
	}
	return http.Serve(lis, handler)
}

func ListenAndServeHTTPS(addr string, config *tls.Config, handler http.Handler) error {
	lis, err := ListenTLS("tcp", addr, config)
	if err != nil {
		return err
	}

	return http.Serve(lis, handler)
}
