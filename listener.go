package proxyproto

import "net"

type Listener struct {
	listener net.Listener
}

func WrapListener(l net.Listener) *Listener {
	return &Listener{listener: l}
}

func (l *Listener) Accept() (net.Conn, error) {
	conn, err := l.listener.Accept()
	if err != nil {
		return nil, err
	}
	return WrapConn(conn), nil
}

func (l *Listener) Close() error {
	return l.listener.Close()
}

func (l *Listener) Addr() net.Addr {
	return l.listener.Addr()
}
