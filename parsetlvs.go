package proxyproto

import "encoding/binary"

// processes the Type-Length-Value bits for Proxy Protocol V2
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
