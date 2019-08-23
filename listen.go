package proxyproto

import (
	"crypto/tls"
	"net"
	"net/http"
)

// Listen is a shortcut equivalent to wrapping net.Listen() with Proxy Protocol v1/v2
func Listen(network, addr string) (net.Listener, error) {
	lis, err := net.Listen(network, addr)
	if err != nil {
		return nil, err
	}
	return WrapListener(lis), nil
}

// ListenTLS is a shortcut equivalent to wrapping tls.Listen() with Proxy Protocol v1/v2
func ListenTLS(network, addr string, config *tls.Config) (net.Listener, error) {
	lis, err := tls.Listen(network, addr, config)
	if err != nil {
		return nil, err
	}
	return WrapListener(lis), nil
}

// ListenAndServeHTTP is a shortcut equivalent to wrapping http.ListenAndServe with Proxy Protocol v1/v2
func ListenAndServeHTTP(addr string, handler http.Handler) error {
	lis, err := Listen("tcp", addr)
	if err != nil {
		return err
	}
	return http.Serve(lis, handler)
}

// ListenAndServeHTTPS is a shortcut equivalent to wrapping http.ListenAndServeTLS with Proxy Protocol v1/v2
func ListenAndServeHTTPS(addr string, config *tls.Config, handler http.Handler) error {
	lis, err := ListenTLS("tcp", addr, config)
	if err != nil {
		return err
	}

	return http.Serve(lis, handler)
}
