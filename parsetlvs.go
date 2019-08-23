package proxyproto

import "encoding/binary"

// parseTLVs processes the Type-Length-Value bits for Proxy Protocol V2
// the buffer is expected to only include the TLV portion of the payload
// it can also be used to process the SSL sub-TLVs by passing that buffer
// into this function
func parseTLVs(buf []byte) map[TLVType][]byte {
	m := make(map[TLVType][]byte)
	i := 0
	for i+2 < len(buf) {
		t := buf[i]
		l := int(binary.BigEndian.Uint16(buf[i+1 : i+3]))

		i += 3
		if i+l <= len(buf) {
			m[TLVType(t)] = buf[i : i+l]
		}
		i += l
	}
	return m
}

// TLVGetALPN gets the ALPN TLV from the data.
// It is for Application-Layer Protocol Negotiation (ALPN). It is a byte sequence defining
// the upper layer protocol in use over the connection. The most common use case
// will be to pass the exact copy of the ALPN extension of the Transport Layer
// Security (TLS) protocol as defined by RFC7301.
// The second return value will be false if the TLV is not provided
func (d *Data) TLVGetALPN() (string, bool) {
	if d.TLVs == nil {
		return "", false
	}
	if d, ok := d.TLVs[TLVTypeALPN]; ok {
		return string(d), true
	}
	return "", false
}

// TLVGetAuthority gets the host name value passed by the client, as an UTF8-encoded string.
// In case of TLS being used on the client connection, this is the exact copy of
// the "server_name" extension as defined by RFC3546
// The second return value will be false if the TLV is not provided
func (d *Data) TLVGetAuthority() (string, bool) {
	if d.TLVs == nil {
		return "", false
	}
	if d, ok := d.TLVs[TLVTypeAuthority]; ok {
		return string(d), true
	}
	return "", false
}

// TLVGetCRC32Checksum gets a 32-bit number storing the CRC32c checksum of the PROXY protocol header
// The second return value will be false if the TLV is not provided
func (d *Data) TLVGetCRC32Checksum() (uint32, bool) {
	if d.TLVs == nil {
		return 0, false
	}
	if d, ok := d.TLVs[TLVTypeCRC32C]; ok && len(d) == 4 {
		return binary.BigEndian.Uint32(d), true
	}
	return 0, false
}

// TLVGetSSL gets the SSL TLV
// The second return value will be false if the TLV is not provided
func (d *Data) TLVGetSSL() (*SSLTLVData, bool) {
	if d.TLVs == nil {
		return nil, false
	}
	if d, ok := d.TLVs[TLVTypeSSL]; ok && len(d) > 5 {
		subs := parseTLVs(d[5:])
		dest := make(map[SSLTLVSubType][]byte)
		for k := range subs {
			dest[SSLTLVSubType(k)] = subs[k]
		}

		return &SSLTLVData{
			Client:   SSLTLVClientField(d[0]),
			Verified: binary.BigEndian.Uint32(d[1:5]) == 0,
			SubTLVs:  dest,
		}, true
	}
	return nil, false
}

// TLVGetNetworkNamespace gets the value as the US-ASCII string representation
// of the namespace's name.
// The second return value will be false if the TLV is not provided
func (d *Data) TLVGetNetworkNamespace() (string, bool) {
	if d.TLVs == nil {
		return "", false
	}
	if d, ok := d.TLVs[TLVTypeNetNS]; ok {
		return string(d), true
	}
	return "", false
}
