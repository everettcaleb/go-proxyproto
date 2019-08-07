package proxyproto

import "encoding/binary"

// ParseV2 takes raw packet data and attempts to parse Proxy Protocol v2 ONLY
// if the data does not match Proxy Protocol v2 or contains unspecified content
// this function returns nil. For AddressFamily IPv4 and IPv6 you can safely cast
// the SourceAddr and DestAddr to the Go built-in net.IP type. For Unix,
// you can treat them as null-terminated strings.
func ParseV2(buf []byte) *Data {
	if len(buf) < 16 {
		return nil
	}
	// Check the prefix (except the first byte)
	for i := 1; i < 12; i++ {
		if buf[i] != protov2[i] {
			return nil
		}
	}
	// Check version and proxy/local
	var payloadSize = int(binary.BigEndian.Uint16(buf[14:16]))
	switch buf[12] {
	case verCmdUpper4 + verCmdLowerLocal:
		return &Data{
			DataOffset: payloadSize + 16,
		}
	case verCmdUpper4 + verCmdLowerProxy:
	default:
		return nil
	}

	// Check length for sanity
	if len(buf) < payloadSize+16 {
		return nil
	}

	// Check address family
	var af AddressFamily
	var addrSize int

	switch buf[13] & 0xf0 {
	case afpUpperUnspec:
		return nil
	case afpUpperIPv4:
		af = AddressFamilyIPv4
		addrSize = 4
	case afpUpperIPv6:
		af = AddressFamilyIPv6
		addrSize = 16
	case afpUpperUnix:
		af = AddressFamilyUnix
		addrSize = 108
	}

	// Check transport
	var tr Transport
	switch buf[13] & 0xf {
	case afpLowerUnspec:
		return nil
	case afpLowerStream:
		tr = TransportStream
	case afpLowerDgram:
		tr = TransportDgram
	}

	// Extract port values
	var sp int
	var dp int
	if af != AddressFamilyUnix {
		sp = int(binary.BigEndian.Uint16(buf[addrSize*2+16 : addrSize*2+18]))
		dp = int(binary.BigEndian.Uint16(buf[addrSize*2+18 : addrSize*2+20]))
	}

	// Check for TLVs
	var tlvs map[TLVType][]byte
	if payloadSize > addrSize*2+4 {
		tlvs = parseTLVs(buf[addrSize*2+20 : payloadSize+16])
	}

	return &Data{
		AddressFamily: af,
		Transport:     tr,
		DataOffset:    payloadSize + 16,
		SourceAddr:    buf[16 : addrSize+16],
		DestAddr:      buf[16+addrSize : addrSize*2+16],
		SourcePort:    sp,
		DestPort:      dp,
		TLVs:          tlvs,
	}
}
