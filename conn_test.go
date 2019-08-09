package proxyproto

import (
	"net"
	"testing"
)

func TestConn_Read(t *testing.T) {
	type args struct {
		b []byte
	}
	tests := []struct {
		name    string
		conn    net.Conn
		args    args
		want    int
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Conn{
				conn: tt.conn,
			}
			got, err := c.Read(tt.args.b)
			if (err != nil) != tt.wantErr {
				t.Errorf("Conn.Read() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("Conn.Read() = %v, want %v", got, tt.want)
			}
		})
	}
}
