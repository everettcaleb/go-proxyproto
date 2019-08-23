package proxyproto

import (
	"net"
	"strconv"
	"strings"
)

const (
	// 108 bytes is the ideal buffer size for proxy proto v1
	v1BufSize = 108

	// 56 chars is the max len for TCP4 (minus 10)
	v1Tcp4MaxSize = 56

	// AddressFamilyLocal means the address type was specified as "unspec" (v1) or "local" (v2)
	AddressFamilyLocal AddressFamily = 0
	// AddressFamilyIPv4 means the address type is IPv4
	AddressFamilyIPv4 AddressFamily = 1
	// AddressFamilyIPv6 means the address type is IPv6
	AddressFamilyIPv6 AddressFamily = 2
	// AddressFamilyUnix means the address type is a Unix socket address (v2 only)
	AddressFamilyUnix AddressFamily = 3

	// TransportUnspec means the transport was unspecified (v2 only)
	TransportUnspec Transport = 0
	// TransportStream means the transport is TCP (Stream) (v1 or v2)
	TransportStream Transport = 1
	// TransportDgram means the transport is UDP (Datagram) (v2 only)
	TransportDgram Transport = 2

	// TLVTypeALPN is for Application-Layer Protocol Negotiation (ALPN). It is a byte sequence defining
	// the upper layer protocol in use over the connection. The most common use case
	// will be to pass the exact copy of the ALPN extension of the Transport Layer
	// Security (TLS) protocol as defined by RFC7301
	TLVTypeALPN TLVType = 0x1
	// TLVTypeAuthority contains the host name value passed by the client, as an UTF8-encoded string.
	// In case of TLS being used on the client connection, this is the exact copy of
	// the "server_name" extension as defined by RFC3546
	TLVTypeAuthority TLVType = 0x2
	// TLVTypeCRC32C is a 32-bit number storing the CRC32c checksum of the PROXY protocol header
	TLVTypeCRC32C TLVType = 0x3
	// TLVTypeNoop should be ignored when parsed. The value is zero or more bytes.
	// Can be used for data padding or alignment
	TLVTypeNoop TLVType = 0x4
	// TLVTypeSSL indicates that the client connected over SSL/TLS and may contain sub-TLVs
	TLVTypeSSL TLVType = 0x20
	// TLVTypeNetNS defines the value as the US-ASCII string representation
	// of the namespace's name.
	TLVTypeNetNS TLVType = 0x30

	// TLVSubTypeSSLVersion is the US-ASCII string representation of the TLS version
	TLVSubTypeSSLVersion SSLTLVSubType = 0x21
	// TLVSubTypeSSLCN is the string representation (in UTF8) of the Common Name field
	// (OID: 2.5.4.3) of the client certificate's Distinguished Name
	TLVSubTypeSSLCN SSLTLVSubType = 0x22
	// TLVSubTypeSSLCipher provides the US-ASCII string name
	// of the used cipher, for example "ECDHE-RSA-AES128-GCM-SHA256"
	TLVSubTypeSSLCipher SSLTLVSubType = 0x23
	// TLVSubTypeSSLSigAlg provides the US-ASCII string name
	// of the algorithm used to sign the certificate presented by the frontend when
	// the incoming connection was made over an SSL/TLS transport layer, for example
	// "SHA256".
	TLVSubTypeSSLSigAlg SSLTLVSubType = 0x24
	// TLVSubTypeSSLKeyAlg provides the US-ASCII string name
	// of the algorithm used to generate the key of the certificate presented by the
	// frontend when the incoming connection was made over an SSL/TLS transport layer,
	// for example "RSA2048".
	TLVSubTypeSSLKeyAlg SSLTLVSubType = 0x25

	// TLVSSLClientSSL bit-flag indicates that the client connected over SSL/TLS
	TLVSSLClientSSL SSLTLVClientField = 0x1
	// TLVSSLClientCertConn bit-flag indicates that the client provided a certificate over the current connection
	TLVSSLClientCertConn SSLTLVClientField = 0x2
	// TLVSSLClientCertSess bit-flag indicates that the client provided a
	// certificate at least once over the TLS session this connection belongs to.
	TLVSSLClientCertSess SSLTLVClientField = 0x4
)

var (
	// value is "PROXY "
	protov1 = [6]byte{0x50, 0x52, 0x4F, 0x58, 0x59, 0x20}
	// value is "TCP4 "
	inetProtoTCP4 = [5]byte{0x54, 0x43, 0x50, 0x34, 0x20}
	// value is "TCP6 "
	inetProtoTCP6 = [5]byte{0x54, 0x43, 0x50, 0x36, 0x20}
	// value is "UNKNOWN"
	inetProtoUnknown = [8]byte{0x55, 0x4E, 0x4B, 0x4E, 0x4F, 0x57, 0x4E}
	// value is "\r\n"
	lineCrLf = [2]byte{0x0D, 0x0A}

	// value is binary for best performance
	protov2 = [12]byte{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A}
	// upper 4 bits of version/command byte should be 0x2
	verCmdUpper4 = byte(0x20)
	// lower 4 bits of version/command byte signaling load balancer local
	// communication (discard rest of proxy info and treat as direct connection)
	verCmdLowerLocal = byte(0x0)
	// lower 4 bits of version/command byte signaling normal proxy proto
	verCmdLowerProxy = byte(0x1)
	// upper 4 bits of af/proto uses an unspecified address family
	afpUpperUnspec = byte(0x0)
	// upper 4 bits of af/proto uses IPv4
	afpUpperIPv4 = byte(0x10)
	// upper 4 bits of af/proto uses IPv6
	afpUpperIPv6 = byte(0x20)
	// upper 4 bits of af/proto uses Unix
	afpUpperUnix = byte(0x30)
	// lower 4 bits of af/proto uses an unspecified transport
	afpLowerUnspec = byte(0x0)
	// lower 4 bits of af/proto uses TCP (STREAM)
	afpLowerStream = byte(0x1)
	// lower 4 bits of af/proto uses UDP (DGRAM)
	afpLowerDgram = byte(0x2)
)

// AddressFamily is the address family used (this tells you how to deal with the Addr data)
// If it's AddressFamilyIPv4 or AddressFamilyIPv6 you can
// safely cast SourceAddr or DestAddr to net.IP. AddressFamilyUnix means treat the
// address fields as if they were null terminated ASCII strings. AddressFamilyLocal means
// that the packet came from the proxy itself.
type AddressFamily int

// Transport is the transport used. This will only be unspecified for the Local address family
// Any other case will be discarded
type Transport int

// TLVType is the "type" portion of type-length-value
type TLVType byte

// SSLTLVSubType is the "sub-type" port of the SSL type-length-value entry
type SSLTLVSubType byte

// SSLTLVClientField is a bit-field indicating what the client provided
type SSLTLVClientField byte

// Data represents the version-independent data captured via Proxy Protocol
type Data struct {
	AddressFamily AddressFamily
	Transport     Transport
	SourceAddr    []byte
	DestAddr      []byte
	SourcePort    int
	DestPort      int
	TLVs          map[TLVType][]byte
	remainingData []byte
}

// Source gets the source as a net.Addr
func (d *Data) Source() net.Addr {
	return &dataAddr{
		AddressFamily: d.AddressFamily,
		Transport:     d.Transport,
		Addr:          d.SourceAddr,
		Port:          d.SourcePort,
	}
}

// Dest gets the destination as a net.Addr
func (d *Data) Dest() net.Addr {
	return &dataAddr{
		AddressFamily: d.AddressFamily,
		Transport:     d.Transport,
		Addr:          d.DestAddr,
		Port:          d.DestPort,
	}
}

type dataAddr struct {
	AddressFamily AddressFamily
	Transport     Transport
	Addr          []byte
	Port          int
}

func (a *dataAddr) Network() string {
	if a.Transport == TransportStream {
		if a.AddressFamily == AddressFamilyIPv4 {
			return "tcp4"
		}
		if a.AddressFamily == AddressFamilyIPv6 {
			return "tcp6"
		}
		if a.AddressFamily == AddressFamilyUnix {
			return "unix"
		}
	}
	if a.Transport == TransportDgram {
		if a.AddressFamily == AddressFamilyIPv4 {
			return "udp4"
		}
		if a.AddressFamily == AddressFamilyIPv6 {
			return "udp6"
		}
		if a.AddressFamily == AddressFamilyUnix {
			return "unixpacket"
		}
	}
	return ""
}

func (a *dataAddr) String() string {
	if a.AddressFamily == AddressFamilyIPv4 || a.AddressFamily == AddressFamilyIPv6 {
		return strings.Join([]string{
			net.IP(a.Addr).String(),
			strconv.Itoa(a.Port),
		}, ":")
	}
	if a.AddressFamily == AddressFamilyUnix {
		return string(a.Addr)
	}
	return ""
}

// SSLTLVData contains information about any client-presented TLS certificate
type SSLTLVData struct {
	Client   SSLTLVClientField
	Verified bool
	SubTLVs  map[SSLTLVSubType][]byte
}

// TLVSSLVersion the TLS version used, the second return value will be false if this is not present
func (d *SSLTLVData) TLVSSLVersion() (string, bool) {
	if d.SubTLVs == nil {
		return "", false
	}
	if d, ok := d.SubTLVs[TLVSubTypeSSLVersion]; ok {
		return string(d), true
	}
	return "", false
}

// TLVSSLCommonName the certificate common name presented, the second return value will be false if this is not present
func (d *SSLTLVData) TLVSSLCommonName() (string, bool) {
	if d.SubTLVs == nil {
		return "", false
	}
	if d, ok := d.SubTLVs[TLVSubTypeSSLCN]; ok {
		return string(d), true
	}
	return "", false
}

// TLVSSLCipher the TLS cipher used, the second return value will be false if this is not present
func (d *SSLTLVData) TLVSSLCipher() (string, bool) {
	if d.SubTLVs == nil {
		return "", false
	}
	if d, ok := d.SubTLVs[TLVSubTypeSSLCipher]; ok {
		return string(d), true
	}
	return "", false
}

// TLVSSLSigAlg the TLS signature algo used, the second return value will be false if this is not present
func (d *SSLTLVData) TLVSSLSigAlg() (string, bool) {
	if d.SubTLVs == nil {
		return "", false
	}
	if d, ok := d.SubTLVs[TLVSubTypeSSLSigAlg]; ok {
		return string(d), true
	}
	return "", false
}

// TLVSSLKeyAlg the TLS key algo used, the second return value will be false if this is not present
func (d *SSLTLVData) TLVSSLKeyAlg() (string, bool) {
	if d.SubTLVs == nil {
		return "", false
	}
	if d, ok := d.SubTLVs[TLVSubTypeSSLKeyAlg]; ok {
		return string(d), true
	}
	return "", false
}
