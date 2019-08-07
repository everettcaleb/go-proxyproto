package proxyproto

import (
	"net"
	"reflect"
	"testing"
)

func Test_binVarsV1(t *testing.T) {
	v := string(protov1[:])
	if v != "PROXY" {
		t.Errorf("expected protov1 to be \"PROXY\", got %s", v)
	}
	v = string(inetProtoTCP4[:])
	if v != "TCP4" {
		t.Errorf("expected inetProtoTCP4 to be \"TCP4\", got %s", v)
	}
	v = string(inetProtoTCP6[:])
	if v != "TCP6" {
		t.Errorf("expected inetProtoTCP6 to be \"TCP6\", got %s", v)
	}
}

func Test_process(t *testing.T) {
	tests := []struct {
		name string
		buf  []byte
		want *Data
	}{
		{
			name: "valid 4",
			buf:  []byte("PROXY TCP4 10.20.30.40 40.30.20.10 8000 9000\r\nTEST"),
			want: &Data{
				DataOffset:    46,
				AddressFamily: AddressFamilyIPv4,
				Transport:     TransportStream,
				SourceAddr:    net.IPv4(10, 20, 30, 40),
				SourcePort:    8000,
				DestAddr:      net.IPv4(40, 30, 20, 10),
				DestPort:      9000,
			},
		},
		{
			name: "valid 6",
			buf:  []byte("PROXY TCP6 2607:f8b0:4008:80e::200e 2606:4700:4700::1111 8000 9000\r\nTEST"),
			want: &Data{
				DataOffset:    68,
				AddressFamily: AddressFamilyIPv6,
				Transport:     TransportStream,
				SourceAddr:    []byte{0x26, 0x7, 0xf8, 0xb0, 0x40, 0x8, 0x8, 0xe, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x20, 0x0e},
				SourcePort:    8000,
				DestAddr:      []byte{0x26, 0x6, 0x47, 0x0, 0x47, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x11, 0x11},
				DestPort:      9000,
			},
		},
		{
			name: "valid tcp4 proxy",
			buf: []byte{
				// header
				0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
				// version/command
				0x21,
				// address family / transport
				0x11,
				// length
				0x0, 0xc,
				// source addr
				10, 20, 30, 40,
				// dest addr
				40, 30, 20, 10,
				// source port
				0x1f, 0x40,
				// dest port
				0x23, 0x28,

				// random data
				0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8,
			},
			want: &Data{
				DataOffset:    28,
				AddressFamily: AddressFamilyIPv4,
				Transport:     TransportStream,
				SourceAddr:    []byte{10, 20, 30, 40},
				SourcePort:    8000,
				DestAddr:      []byte{40, 30, 20, 10},
				DestPort:      9000,
			},
		},
		{
			name: "valid tcp4 proxy w TLVs",
			buf: []byte{
				// header
				0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
				// version/command
				0x21,
				// address family / transport
				0x11,
				// length
				0x0, 0x16,
				// source addr
				10, 20, 30, 40,
				// dest addr
				40, 30, 20, 10,
				// source port
				0x1f, 0x40,
				// dest port
				0x23, 0x28,

				// TLV no-op
				0x4, // No-op
				0x0, 0x0,

				// TLV
				0x3, // CRC32C
				0x0, 0x4,
				1, 2, 3, 4,

				// random data
				0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8,
			},
			want: &Data{
				DataOffset:    38,
				AddressFamily: AddressFamilyIPv4,
				Transport:     TransportStream,
				SourceAddr:    []byte{10, 20, 30, 40},
				SourcePort:    8000,
				DestAddr:      []byte{40, 30, 20, 10},
				DestPort:      9000,
				TLVs: map[TLVType][]byte{
					TLVTypeNoop:   []byte{},
					TLVTypeCRC32C: []byte{1, 2, 3, 4},
				},
			},
		},
		{
			name: "valid tcp6 proxy",
			buf: []byte{
				// header
				0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
				// version/command
				0x21,
				// address family / transport
				0x21,
				// length
				0x0, 0x24,
				// source addr
				0x26, 0x7, 0xf8, 0xb0, 0x40, 0x8, 0x8, 0xe, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x20, 0x0e,
				// dest addr
				0x26, 0x6, 0x47, 0x0, 0x47, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x11, 0x11,
				// source port
				0x1f, 0x40,
				// dest port
				0x23, 0x28,

				// random data
				0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8,
			},
			want: &Data{
				DataOffset:    52,
				AddressFamily: AddressFamilyIPv6,
				Transport:     TransportStream,
				SourceAddr:    []byte{0x26, 0x7, 0xf8, 0xb0, 0x40, 0x8, 0x8, 0xe, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x20, 0x0e},
				SourcePort:    8000,
				DestAddr:      []byte{0x26, 0x6, 0x47, 0x0, 0x47, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x11, 0x11},
				DestPort:      9000,
			},
		},
		{
			name: "valid local",
			buf: []byte{
				// header
				0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
				// version/command
				0x20,
				// address family / transport
				0x00,
				// length
				0x0, 0x0,

				// random data
				0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8,
			},
			want: &Data{
				DataOffset:    16,
				AddressFamily: AddressFamilyLocal,
				Transport:     TransportUnspec,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := process(tt.buf)

			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("process() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_processV1(t *testing.T) {
	tests := []struct {
		name string
		buf  []byte
		want *Data
	}{
		{
			name: "valid 4",
			buf:  []byte("PROXY TCP4 10.20.30.40 40.30.20.10 8000 9000\r\nTEST"),
			want: &Data{
				DataOffset:    46,
				AddressFamily: AddressFamilyIPv4,
				Transport:     TransportStream,
				SourceAddr:    net.IPv4(10, 20, 30, 40),
				SourcePort:    8000,
				DestAddr:      net.IPv4(40, 30, 20, 10),
				DestPort:      9000,
			},
		},
		{
			name: "valid 6",
			buf:  []byte("PROXY TCP6 2607:f8b0:4008:80e::200e 2606:4700:4700::1111 8000 9000\r\nTEST"),
			want: &Data{
				DataOffset:    68,
				AddressFamily: AddressFamilyIPv6,
				Transport:     TransportStream,
				SourceAddr:    []byte{0x26, 0x7, 0xf8, 0xb0, 0x40, 0x8, 0x8, 0xe, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x20, 0x0e},
				SourcePort:    8000,
				DestAddr:      []byte{0x26, 0x6, 0x47, 0x0, 0x47, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x11, 0x11},
				DestPort:      9000,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := processV1(tt.buf)

			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("processV1() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_processV2(t *testing.T) {
	tests := []struct {
		name string
		buf  []byte
		want *Data
	}{
		{
			name: "valid tcp4 proxy",
			buf: []byte{
				// header
				0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
				// version/command
				0x21,
				// address family / transport
				0x11,
				// length
				0x0, 0xc,
				// source addr
				10, 20, 30, 40,
				// dest addr
				40, 30, 20, 10,
				// source port
				0x1f, 0x40,
				// dest port
				0x23, 0x28,

				// random data
				0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8,
			},
			want: &Data{
				DataOffset:    28,
				AddressFamily: AddressFamilyIPv4,
				Transport:     TransportStream,
				SourceAddr:    []byte{10, 20, 30, 40},
				SourcePort:    8000,
				DestAddr:      []byte{40, 30, 20, 10},
				DestPort:      9000,
			},
		},
		{
			name: "valid tcp4 proxy w TLVs",
			buf: []byte{
				// header
				0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
				// version/command
				0x21,
				// address family / transport
				0x11,
				// length
				0x0, 0x16,
				// source addr
				10, 20, 30, 40,
				// dest addr
				40, 30, 20, 10,
				// source port
				0x1f, 0x40,
				// dest port
				0x23, 0x28,

				// TLV no-op
				0x4, // No-op
				0x0, 0x0,

				// TLV
				0x3, // CRC32C
				0x0, 0x4,
				1, 2, 3, 4,

				// random data
				0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8,
			},
			want: &Data{
				DataOffset:    38,
				AddressFamily: AddressFamilyIPv4,
				Transport:     TransportStream,
				SourceAddr:    []byte{10, 20, 30, 40},
				SourcePort:    8000,
				DestAddr:      []byte{40, 30, 20, 10},
				DestPort:      9000,
				TLVs: map[TLVType][]byte{
					TLVTypeNoop:   []byte{},
					TLVTypeCRC32C: []byte{1, 2, 3, 4},
				},
			},
		},
		{
			name: "valid tcp6 proxy",
			buf: []byte{
				// header
				0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
				// version/command
				0x21,
				// address family / transport
				0x21,
				// length
				0x0, 0x24,
				// source addr
				0x26, 0x7, 0xf8, 0xb0, 0x40, 0x8, 0x8, 0xe, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x20, 0x0e,
				// dest addr
				0x26, 0x6, 0x47, 0x0, 0x47, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x11, 0x11,
				// source port
				0x1f, 0x40,
				// dest port
				0x23, 0x28,

				// random data
				0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8,
			},
			want: &Data{
				DataOffset:    52,
				AddressFamily: AddressFamilyIPv6,
				Transport:     TransportStream,
				SourceAddr:    []byte{0x26, 0x7, 0xf8, 0xb0, 0x40, 0x8, 0x8, 0xe, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x20, 0x0e},
				SourcePort:    8000,
				DestAddr:      []byte{0x26, 0x6, 0x47, 0x0, 0x47, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x11, 0x11},
				DestPort:      9000,
			},
		},
		{
			name: "valid local",
			buf: []byte{
				// header
				0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
				// version/command
				0x20,
				// address family / transport
				0x00,
				// length
				0x0, 0x0,

				// random data
				0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8,
			},
			want: &Data{
				DataOffset:    16,
				AddressFamily: AddressFamilyLocal,
				Transport:     TransportUnspec,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := processV2(tt.buf)

			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("processV2() = %v, want %v", got, tt.want)
			}
		})
	}
}
