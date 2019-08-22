package proxyproto

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
)

func parseV2(buf []byte, r io.Reader) (*Data, error) {
	// Check version and proxy/local
	payloadSize := int(binary.BigEndian.Uint16(buf[2:4]))
	switch buf[0] {
	case verCmdUpper4 + verCmdLowerLocal:
		return &Data{
			remainingData: buf[payloadSize+4:],
		}, nil
	case verCmdUpper4 + verCmdLowerProxy:
	default:
		return nil, ParseError("failed to parse proxy protocol v2: invalid version/command byte")
	}
	aftp := buf[1]
	buf = buf[4:]

	// Check length for sanity, attempt to read more if we need more data
	var rb []byte
	for len(buf) < payloadSize {
		if rb == nil {
			rb = make([]byte, parseReadSize)
		}
		n, err := r.Read(rb)
		if err != nil {
			return nil, fmt.Errorf("payload size (%v) exceeded buffer length (%v) but failed to read more data: %v", payloadSize, len(buf), err)
		}
		buf = bytes.Join([][]byte{buf, rb[:n]}, nil)
	}

	// Check address family
	var af AddressFamily
	var addrSize int

	switch aftp & 0xf0 {
	case afpUpperUnspec:
	case afpUpperIPv4:
		af = AddressFamilyIPv4
		addrSize = 4
	case afpUpperIPv6:
		af = AddressFamilyIPv6
		addrSize = 16
	case afpUpperUnix:
		af = AddressFamilyUnix
		addrSize = 108
	default:
		return nil, ParseError("failed to parse proxy protocol v2: invalid Address Family nibble")
	}

	// Check transport
	var tr Transport
	switch aftp & 0xf {
	case afpLowerUnspec:
		tr = TransportUnspec
	case afpLowerStream:
		tr = TransportStream
	case afpLowerDgram:
		tr = TransportDgram
	default:
		return nil, ParseError("failed to parse proxy protocol v2: invalid Transport nibble")
	}

	// Extract port values
	var sp int
	var dp int
	if af == AddressFamilyIPv4 || af == AddressFamilyIPv6 {
		sp = int(binary.BigEndian.Uint16(buf[addrSize*2 : addrSize*2+2]))
		dp = int(binary.BigEndian.Uint16(buf[addrSize*2+2 : addrSize*2+4]))
	}

	// Check for TLVs
	var tlvs map[TLVType][]byte
	if payloadSize > addrSize*2+4 {
		tlvs = parseTLVs(buf[addrSize*2+4 : payloadSize])
	}

	return &Data{
		AddressFamily: af,
		Transport:     tr,
		remainingData: buf[payloadSize:],
		SourceAddr:    buf[:addrSize],
		DestAddr:      buf[addrSize : addrSize*2],
		SourcePort:    sp,
		DestPort:      dp,
		TLVs:          tlvs,
	}, nil
}
