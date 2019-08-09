package proxyproto

import (
	"net"
	"time"
)

type Conn struct {
	conn      net.Conn
	protoData *Data
}

// Wrap wraps the specified network connection in Proxy Protocol parsing logic.
// The first bytes read from the connection will be used to populate the proxy data.
func Wrap(conn net.Conn) *Conn {
	return &Conn{conn: conn}
}

// ProxyData retrieves proxy data cached after initial read, may be nil if Read() hasn't
// been called.
func (c *Conn) ProxyData() *Data {
	return c.protoData
}

// Read reads data from the connection. Initial read uses an internal buffer
// and will be parsed as Proxy Protocol v1 or v2. Subsequent reads will read
// directly from the connection once parsing completes and the internal buffer is empty.
// Read can be made to time out and return an Error with Timeout() == true
// after a fixed time limit; see SetDeadline and SetReadDeadline.
func (c *Conn) Read(b []byte) (int, error) {
	if c.protoData == nil {
		d, err := Parse(c.conn)
		if err != nil {
			return 0, err
		}
		c.protoData = d
	}
	if c.protoData != nil && len(c.protoData.remainingData) > 0 {
		n := len(c.protoData.remainingData)
		bc := cap(b)
		if bc > n {
			b = b[:n]
			for i := 0; i < n; i++ {
				b[i] = c.protoData.remainingData[i]
			}
			return n, nil
		}
		b = b[:bc]
		for i := 0; i < bc; i++ {
			b[i] = c.protoData.remainingData[i]
		}
		c.protoData.remainingData = c.protoData.remainingData[bc:]
		return bc, nil
	}
	return c.conn.Read(b)
}

// Write writes data to the connection.
// Write can be made to time out and return an Error with Timeout() == true
// after a fixed time limit; see SetDeadline and SetWriteDeadline.
func (c *Conn) Write(b []byte) (n int, err error) {
	return c.conn.Write(b)
}

// Close closes the connection.
// Any blocked Read or Write operations will be unblocked and return errors.
func (c *Conn) Close() error {
	return c.conn.Close()
}

// LocalAddr returns the local network address.
func (c *Conn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

// RemoteAddr returns the remote network address.
func (c *Conn) RemoteAddr() net.Addr {
	if c.protoData == nil {
		return c.conn.RemoteAddr()
	}
	return c.protoData.Source()
}

// SetDeadline sets the read and write deadlines associated
// with the connection. It is equivalent to calling both
// SetReadDeadline and SetWriteDeadline.
//
// A deadline is an absolute time after which I/O operations
// fail with a timeout (see type Error) instead of
// blocking. The deadline applies to all future and pending
// I/O, not just the immediately following call to Read or
// Write. After a deadline has been exceeded, the connection
// can be refreshed by setting a deadline in the future.
//
// An idle timeout can be implemented by repeatedly extending
// the deadline after successful Read or Write calls.
//
// A zero value for t means I/O operations will not time out.
func (c *Conn) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

// SetReadDeadline sets the deadline for future Read calls
// and any currently-blocked Read call.
// A zero value for t means Read will not time out.
func (c *Conn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

// SetWriteDeadline sets the deadline for future Write calls
// and any currently-blocked Write call.
// Even if write times out, it may return n > 0, indicating that
// some of the data was successfully written.
// A zero value for t means Write will not time out.
func (c *Conn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}
