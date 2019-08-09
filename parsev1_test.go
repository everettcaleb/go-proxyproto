package proxyproto

import (
	"net"
	"reflect"
	"testing"
)

func Test_parseV1(t *testing.T) {
	tests := []struct {
		name    string
		buf     []byte
		want    *Data
		wantErr error
	}{
		{
			name: "valid 4",
			buf:  []byte("TCP4 10.20.30.40 40.30.20.10 8000 9000\r\nTEST"), // Removed "PROXY "
			want: &Data{
				remainingData: []byte("TEST"),
				AddressFamily: AddressFamilyIPv4,
				Transport:     TransportStream,
				SourceAddr:    net.IPv4(10, 20, 30, 40),
				SourcePort:    8000,
				DestAddr:      net.IPv4(40, 30, 20, 10),
				DestPort:      9000,
			},
			wantErr: nil,
		},
		{
			name: "valid 6",
			buf:  []byte("TCP6 2607:f8b0:4008:80e::200e 2606:4700:4700::1111 8000 9000\r\nTEST"), // Removed "PROXY "
			want: &Data{
				remainingData: []byte("TEST"),
				AddressFamily: AddressFamilyIPv6,
				Transport:     TransportStream,
				SourceAddr:    []byte{0x26, 0x7, 0xf8, 0xb0, 0x40, 0x8, 0x8, 0xe, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x20, 0x0e},
				SourcePort:    8000,
				DestAddr:      []byte{0x26, 0x6, 0x47, 0x0, 0x47, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x11, 0x11},
				DestPort:      9000,
			},
			wantErr: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseV1(tt.buf)

			if tt.wantErr != err {
				t.Fatalf("parseV1() err = %v, want %v", err, tt.wantErr)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("parseV1() = %v, want %v", got, tt.want)
			}
		})
	}
}
