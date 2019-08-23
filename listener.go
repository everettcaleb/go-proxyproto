package proxyproto

import (
	"net"
)

// Listener is an implementation of net.Listener that supports
// automatic parsing of Proxy Protocol v1/v2. See also, Listen, ListenTLS,
// ListenAndServeHTTP, and ListenAndServeHTTPS which are likely more convenient to use.
type Listener struct {
	listener net.Listener
}

// WrapListener takes an existing listener and wraps proxy protocol
// functionality around it. Any accepted connections will expect
// proxy protocol.
func WrapListener(l net.Listener) *Listener {
	return &Listener{listener: l}
}

// Accept waits for and returns the next connection to the listener.
// The connection will be wrapped automatically as a proxyproto.Conn using WrapConn()
func (l *Listener) Accept() (net.Conn, error) {
	conn, err := l.listener.Accept()
	if err != nil {
		return nil, err
	}
	return WrapConn(conn)
}

// Close closes the listener.
// Any blocked Accept operations will be unblocked and return errors.
func (l *Listener) Close() error {
	return l.listener.Close()
}

// Addr returns the listener's network address.
func (l *Listener) Addr() net.Addr {
	return l.listener.Addr()
}
