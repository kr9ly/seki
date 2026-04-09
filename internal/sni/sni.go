package sni

// Extract parses a TLS ClientHello and returns the SNI server name.
// Returns empty string if the data is not a TLS ClientHello or has no SNI extension.
func Extract(data []byte) string {
	// TLS record: content_type(1) + version(2) + length(2)
	if len(data) < 5 || data[0] != 0x16 {
		return ""
	}
	recordLen := int(data[3])<<8 | int(data[4])
	if len(data) < 5+recordLen {
		return ""
	}
	fragment := data[5 : 5+recordLen]

	// Handshake: msg_type(1) + length(3)
	if len(fragment) < 4 || fragment[0] != 0x01 {
		return ""
	}
	hsLen := int(fragment[1])<<16 | int(fragment[2])<<8 | int(fragment[3])
	if len(fragment) < 4+hsLen {
		return ""
	}
	body := fragment[4 : 4+hsLen]

	// ClientHello: version(2) + random(32) + session_id(var) + cipher_suites(var) + compression(var) + extensions(var)
	if len(body) < 34 {
		return ""
	}
	pos := 34

	// Skip session_id
	if pos >= len(body) {
		return ""
	}
	pos += 1 + int(body[pos])

	// Skip cipher_suites
	if pos+2 > len(body) {
		return ""
	}
	pos += 2 + (int(body[pos])<<8 | int(body[pos+1]))

	// Skip compression_methods
	if pos >= len(body) {
		return ""
	}
	pos += 1 + int(body[pos])

	// Extensions
	if pos+2 > len(body) {
		return ""
	}
	extLen := int(body[pos])<<8 | int(body[pos+1])
	pos += 2
	extEnd := pos + extLen
	if extEnd > len(body) {
		return ""
	}

	for pos+4 <= extEnd {
		extType := int(body[pos])<<8 | int(body[pos+1])
		extDataLen := int(body[pos+2])<<8 | int(body[pos+3])
		pos += 4
		if pos+extDataLen > extEnd {
			break
		}
		if extType == 0 { // server_name
			return parseServerName(body[pos : pos+extDataLen])
		}
		pos += extDataLen
	}

	return ""
}

func parseServerName(data []byte) string {
	if len(data) < 2 {
		return ""
	}
	listLen := int(data[0])<<8 | int(data[1])
	if len(data) < 2+listLen {
		return ""
	}
	offset := 2
	for offset+3 <= 2+listLen {
		nameType := data[offset]
		nameLen := int(data[offset+1])<<8 | int(data[offset+2])
		offset += 3
		if nameType == 0 && offset+nameLen <= len(data) {
			return string(data[offset : offset+nameLen])
		}
		offset += nameLen
	}
	return ""
}
