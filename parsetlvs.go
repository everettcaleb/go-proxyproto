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

func (d *Data) TLVGetALPN() (string, bool) {
	if d.TLVs == nil {
		return "", false
	}
	if d, ok := d.TLVs[TLVTypeALPN]; ok {
		return string(d), true
	}
	return "", false
}

func (d *Data) TLVGetAuthority() (string, bool) {
	if d.TLVs == nil {
		return "", false
	}
	if d, ok := d.TLVs[TLVTypeAuthority]; ok {
		return string(d), true
	}
	return "", false
}

func (d *Data) TLVGetCRC32Checksum() (uint32, bool) {
	if d.TLVs == nil {
		return 0, false
	}
	if d, ok := d.TLVs[TLVTypeCRC32C]; ok && len(d) == 4 {
		return binary.BigEndian.Uint32(d), true
	}
	return 0, false
}

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

func (d *Data) TLVGetNetworkNamespace() (string, bool) {
	if d.TLVs == nil {
		return "", false
	}
	if d, ok := d.TLVs[TLVTypeNetNS]; ok {
		return string(d), true
	}
	return "", false
}
