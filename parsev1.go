package proxyproto

import (
	"net"
	"strconv"
)

// ParseV1 takes raw packet data and attempts to parse Proxy Protocol v1 ONLY
// if the data does not match Proxy Protocol v1 or uses unknown
// this function returns nil. TLVs will always be nil. You can safely cast the
// SourceAddr and DestAddr to the Go built-in net.IP type.
// Note: doesn't check the first char since typically Parse() checks that
// The first char is expected to be 'P'
func ParseV1(buf []byte) *Data {
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
		return parseV1TCP(buf, AddressFamilyIPv4, v1Tcp4MaxSize)
	case inetProtoTCP6[3]: // "6"
		return parseV1TCP(buf, AddressFamilyIPv6, v1BufSize)
	}

	return nil
}

// processes Proxy Protocol V1 for TCP only
// note: skip the first 10 characters ("PROXY TCP#")
// since those are checked by processV1
func parseV1TCP(buf []byte, af AddressFamily, maxSize int) *Data {
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
