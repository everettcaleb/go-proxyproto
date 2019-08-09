package proxyproto

import (
	"bytes"
	"net"
	"strconv"
)

func parseV1(c []byte) (*Data, error) {
	switch {
	case bytes.HasPrefix(c, inetProtoTCP4[:]):
		return parseV1TCP(c[len(inetProtoTCP4):], AddressFamilyIPv4, v1Tcp4MaxSize)
	case bytes.HasPrefix(c, inetProtoTCP6[:]):
		return parseV1TCP(c[len(inetProtoTCP6):], AddressFamilyIPv6, v1BufSize)
	case bytes.HasPrefix(c, inetProtoUnknown[:]):
		c = c[len(inetProtoUnknown):]
		crlf := bytes.Index(c, lineCrLf[:])
		if crlf < 0 {
			return nil, ParseError("failed to parse proxy protocol v1: expected CR/LF in buffer")
		}
		return &Data{
			remainingData: c[len(inetProtoUnknown)+crlf:],
		}, nil
	default:
		return nil, ParseError("failed to parse proxy protocol v1: expected \"TCP4\", \"TCP6\", or \"UNKNOWN\" after \"PROXY\"")
	}
}

func parseV1TCP(buf []byte, af AddressFamily, maxSize int) (*Data, error) {
	// read until next space for source IP
	srcIPStart := 0
	srcIPEnd := srcIPStart // this will be the space after the source IP
	for i := srcIPStart; i < len(buf) && i < maxSize; i++ {
		if buf[i] == 0x20 {
			srcIPEnd = i
			break
		}
	}
	if srcIPStart == srcIPEnd {
		return nil, ParseError("failed to parse proxy protocol v1: expected space after source IP")
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
		return nil, ParseError("failed to parse proxy protocol v1: expected space after dest IP")
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
		return nil, ParseError("failed to parse proxy protocol v1: expected space after source port")
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
		return nil, ParseError("failed to parse proxy protocol v1: expected CR after dest port")
	}

	// check LF
	if buf[destPortEnd+1] != 0x0A {
		return nil, ParseError("failed to parse proxy protocol v1: expected LF after CR")
	}

	// parse source IP
	sip := net.ParseIP(string(buf[srcIPStart:srcIPEnd]))
	if sip == nil {
		return nil, fmtParseError("failed to parse proxy protocol v1: failed to parse source IP %q", string(buf[srcIPStart:srcIPEnd]))
	}

	// parse dest IP
	dip := net.ParseIP(string(buf[destIPStart:destIPEnd]))
	if dip == nil {
		return nil, fmtParseError("failed to parse proxy protocol v1: failed to parse dest IP %q", string(buf[destIPStart:destIPEnd]))
	}

	// parse source port
	sp, err := strconv.Atoi(string(buf[srcPortStart:srcPortEnd]))
	if err != nil {
		return nil, fmtParseError("failed to parse proxy protocol v1: failed to parse source port %q: %v", string(buf[srcPortStart:srcPortEnd]), err)
	}

	// parse dest port
	dp, err := strconv.Atoi(string(buf[destPortStart:destPortEnd]))
	if err != nil {
		return nil, fmtParseError("failed to parse proxy protocol v1: failed to parse dest port %q: %v", string(buf[destPortStart:destPortEnd]), err)
	}

	return &Data{
		AddressFamily: af,
		Transport:     TransportStream,
		remainingData: buf[destPortEnd+2:],
		SourceAddr:    []byte(sip),
		DestAddr:      []byte(dip),
		SourcePort:    sp,
		DestPort:      dp,
	}, nil
}
