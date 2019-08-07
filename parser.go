package proxyproto

import (
	"encoding/binary"
	"net"
	"strconv"
)

const (
	// 108 bytes is the ideal buffer size for proxy proto v1
	v1BufSize = 108

	// 56 chars is the max len for TCP4 (minus 10)
	v1Tcp4MaxSize = 56

	AddressFamilyLocal AddressFamily = 0
	AddressFamilyIPv4  AddressFamily = 1
	AddressFamilyIPv6  AddressFamily = 2
	AddressFamilyUnix  AddressFamily = 3

	TransportUnspec Transport = 0
	TransportStream Transport = 1
	TransportDgram  Transport = 2

	TLVTypeALPN          TLVType = 0x1
	TLVTypeAuthority     TLVType = 0x2
	TLVTypeCRC32C        TLVType = 0x3
	TLVTypeNoop          TLVType = 0x4
	TLVTypeSSL           TLVType = 0x20
	TLVSubTypeSSLVersion TLVType = 0x21
	TLVSubTypeSSLCN      TLVType = 0x22
	TLVSubTypeSSLCipher  TLVType = 0x23
	TLVSubTypeSSLSigAlg  TLVType = 0x24
	TLVSubTypeSSLKeyAlg  TLVType = 0x25
	TLVTypeNetNS         TLVType = 0x30
)

var (
	// value is "PROXY"
	protov1 = [5]byte{0x50, 0x52, 0x4F, 0x58, 0x59}
	// value is "TCP4"
	inetProtoTCP4 = [4]byte{0x54, 0x43, 0x50, 0x34}
	// value is "TCP6"
	inetProtoTCP6 = [4]byte{0x54, 0x43, 0x50, 0x36}

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

// Data represents the version independent data captured via Proxy Protocol
type Data struct {
	AddressFamily AddressFamily
	Transport     Transport
	DataOffset    int
	SourceAddr    []byte
	DestAddr      []byte
	SourcePort    int
	DestPort      int
	TLVs          map[TLVType][]byte
}

// processes V1 or V2 (determines which to try by first byte)
func process(buf []byte) *Data {
	// P or 0x0D
	switch buf[0] {
	case protov1[0]: // "P"
		return processV1(buf)
	case protov2[0]: // 0x0D
		return processV2(buf)
	}
	return nil
}

// processes Proxy Protocol V1
// note: doesn't check the first char since process checks that
// also fails on unknown
func processV1(buf []byte) *Data {
	// PROXY
	if buf[1] != protov1[1] {
		return nil
	}
	if buf[2] != protov1[2] {
		return nil
	}
	if buf[3] != protov1[3] {
		return nil
	}
	if buf[4] != protov1[4] {
		return nil
	}
	// " "
	if buf[5] != 0x20 {
		return nil
	}
	// TCP
	if buf[6] != inetProtoTCP4[0] {
		return nil
	}
	if buf[7] != inetProtoTCP4[1] {
		return nil
	}
	if buf[8] != inetProtoTCP4[2] {
		return nil
	}
	// 4, 6
	switch buf[9] {
	case inetProtoTCP4[3]: // "4"
		return processV1TCP(buf, AddressFamilyIPv4, v1Tcp4MaxSize)
	case inetProtoTCP6[3]: // "6"
		return processV1TCP(buf, AddressFamilyIPv6, v1BufSize)
	}

	return nil
}

// processes Proxy Protocol V1 for TCP only
// note: skip the first 10 characters ("PROXY TCP#")
// since those are checked by processV1
func processV1TCP(buf []byte, af AddressFamily, maxSize int) *Data {
	// " "
	if buf[10] != 0x20 {
		return nil
	}

	// read until next space for source IP
	srcIPStart := 11
	srcIPEnd := srcIPStart // this will be the space after the source IP
	for i := srcIPStart; i < len(buf) && i < maxSize; i++ {
		if buf[i] == 0x20 {
			srcIPEnd = i
			break
		}
	}
	if srcIPStart == srcIPEnd {
		return nil
	}

	// read until next space for dest IP
	destIPStart := srcIPEnd + 1
	destIPEnd := destIPStart // this will be the space after the dest IP
	for i := destIPStart; i < len(buf) && i < maxSize; i++ {
		if buf[i] == 0x20 {
			destIPEnd = i
			break
		}
	}
	if destIPStart == destIPEnd {
		return nil
	}

	// read until next space for source port
	srcPortStart := destIPEnd + 1
	srcPortEnd := srcPortStart
	for i := srcPortStart; i < len(buf) && i < maxSize; i++ {
		if buf[i] == 0x20 {
			srcPortEnd = i
			break
		}
	}
	if srcPortStart == srcPortEnd {
		return nil
	}

	// read until CR for dest port
	destPortStart := srcPortEnd + 1
	destPortEnd := destPortStart
	for i := destPortStart; i < len(buf) && i < maxSize; i++ {
		if buf[i] == 0x0D {
			destPortEnd = i
			break
		}
	}
	if destPortStart == destPortEnd {
		return nil
	}

	// check LF
	if buf[destPortEnd+1] != 0x0A {
		return nil
	}

	// parse source IP
	sipstr := string(buf[srcIPStart:srcIPEnd])
	sip := net.ParseIP(sipstr)
	if sip == nil {
		return nil
	}

	// parse dest IP
	dip := net.ParseIP(string(buf[destIPStart:destIPEnd]))
	if dip == nil {
		return nil
	}

	// parse source port
	sp, err := strconv.Atoi(string(buf[srcPortStart:srcPortEnd]))
	if err != nil {
		return nil
	}

	// parse dest port
	dp, err := strconv.Atoi(string(buf[destPortStart:destPortEnd]))
	if err != nil {
		return nil
	}

	// return the index of the first byte that is not part of proxy protocol
	return &Data{
		AddressFamily: af,
		Transport:     TransportStream,
		DataOffset:    destPortEnd + 2,
		SourceAddr:    []byte(sip),
		DestAddr:      []byte(dip),
		SourcePort:    sp,
		DestPort:      dp,
	}
}

// processes Proxy Protocol V2
func processV2(buf []byte) *Data {
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
		tlvs = processV2TLVs(buf[addrSize*2+20 : payloadSize+16])
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

// processes the Type-Length-Value bits for Proxy Protocol V2
// the buffer is expected to only include the TLV portion of the payload
// it can also be used to process the SSL sub-TLVs by passing that buffer
// into this function
func processV2TLVs(buf []byte) map[TLVType][]byte {
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
