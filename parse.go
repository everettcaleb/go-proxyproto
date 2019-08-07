package proxyproto

// Parse takes raw packet data and attempts to parse Proxy Protocol v1/v2
// if the data does not match Proxy Protocol v1/v2 or contains unknown or unspecified content
// this function returns nil. For Proxy Protocol v1, TLVs will always be nil.
// For AddressFamily IPv4 and IPv6 you can safely cast the SourceAddr and DestAddr
// to the Go built-in net.IP type. For Unix, you can treat them as null-terminated strings.
func Parse(buf []byte) *Data {
	// P or 0x0D
	switch buf[0] {
	case protov1[0]: // "P"
		return ParseV1(buf)
	case protov2[0]: // 0x0D
		return ParseV2(buf)
	}
	return nil
}
