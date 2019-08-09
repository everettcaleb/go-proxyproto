package proxyproto

import (
	"bytes"
	"fmt"
	"io"
)

const parseReadSize = 4096

func Parse(r io.Reader) (*Data, error) {
	buf := make([]byte, parseReadSize)
	n, err := r.Read(buf)
	if err != nil {
		return nil, fmt.Errorf("failed to read parser buffer for proxy protocol: %v", err)
	}
	c := buf[:n]

	// v1 or v2
	switch {
	case bytes.HasPrefix(c, protov1[:]):
		return parseV1(c[len(protov1):])
	case bytes.HasPrefix(c, protov2[:]):
		if n < 16 {
			return nil, ParseError("failed to parse proxy protocol v2: header must be at least 16 bytes")
		}
		return parseV2(c[len(protov2):], r)
	default:
		return nil, ParseError("failed to parse proxy protocol, expected \"PROXY\" or v2 binary header")
	}
}

type ParseError string

func (e ParseError) Error() string {
	return string(e)
}

func fmtParseError(format string, a ...interface{}) ParseError {
	return ParseError(fmt.Sprintf(format, a...))
}
