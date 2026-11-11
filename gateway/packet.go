package gateway

import "encoding/binary"

// EchoPort is the UDP port the in-tunnel responder echoes (RFC 862).
const EchoPort = 7

// Respond plays every host inside the tunnel: it answers ICMP and ICMPv6
// echo requests, and echoes UDP datagrams sent to EchoPort. It returns the
// reply packet, or nil if there is nothing to send.
func Respond(pkt []byte) []byte {
	if len(pkt) < 1 {
		return nil
	}
	switch pkt[0] >> 4 {
	case 4:
		return respond4(pkt)
	case 6:
		return respond6(pkt)
	}
	return nil
}

// checksum is the Internet checksum (RFC 1071) of b, starting from sum.
func checksum(sum uint32, b []byte) uint16 {
	for len(b) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(b))
		b = b[2:]
	}
	if len(b) == 1 {
		sum += uint32(b[0]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func respond4(pkt []byte) []byte {
	if len(pkt) < 20 {
		return nil
	}
	ihl := int(pkt[0]&0x0f) * 4
	total := int(binary.BigEndian.Uint16(pkt[2:]))
	if ihl < 20 || total < ihl || total > len(pkt) {
		return nil
	}
	if binary.BigEndian.Uint16(pkt[6:])&0x3fff != 0 {
		return nil // fragments: not worth it
	}
	proto := pkt[9]
	out := append([]byte(nil), pkt[:total]...)
	body := out[ihl:]

	switch {
	case proto == 1 && len(body) >= 8 && body[0] == 8: // ICMP echo request
		body[0] = 0
		body[2], body[3] = 0, 0
		binary.BigEndian.PutUint16(body[2:], checksum(0, body))
	case proto == 17 && len(body) >= 8 && binary.BigEndian.Uint16(body[2:]) == EchoPort:
		sp, dp := binary.BigEndian.Uint16(body[0:]), binary.BigEndian.Uint16(body[2:])
		binary.BigEndian.PutUint16(body[0:], dp)
		binary.BigEndian.PutUint16(body[2:], sp)
		body[6], body[7] = 0, 0 // UDP checksum is optional over IPv4
	default:
		return nil
	}

	// Swap addresses, reset TTL, recompute the header checksum.
	var src [4]byte
	copy(src[:], out[12:16])
	copy(out[12:16], out[16:20])
	copy(out[16:20], src[:])
	out[8] = 64
	out[10], out[11] = 0, 0
	binary.BigEndian.PutUint16(out[10:], checksum(0, out[:ihl]))
	return out
}

func respond6(pkt []byte) []byte {
	if len(pkt) < 40 {
		return nil
	}
	plen := int(binary.BigEndian.Uint16(pkt[4:]))
	if 40+plen > len(pkt) {
		return nil
	}
	next := pkt[6]
	out := append([]byte(nil), pkt[:40+plen]...)
	body := out[40:]

	var src [16]byte
	copy(src[:], out[8:24])
	copy(out[8:24], out[24:40])
	copy(out[24:40], src[:])
	out[7] = 64

	switch {
	case next == 58 && len(body) >= 8 && body[0] == 128: // ICMPv6 echo request
		body[0] = 129
		body[2], body[3] = 0, 0
		binary.BigEndian.PutUint16(body[2:], checksum(pseudo6(out, 58, len(body)), body))
	case next == 17 && len(body) >= 8 && binary.BigEndian.Uint16(body[2:]) == EchoPort:
		sp, dp := binary.BigEndian.Uint16(body[0:]), binary.BigEndian.Uint16(body[2:])
		binary.BigEndian.PutUint16(body[0:], dp)
		binary.BigEndian.PutUint16(body[2:], sp)
		body[6], body[7] = 0, 0
		c := checksum(pseudo6(out, 17, len(body)), body)
		if c == 0 {
			c = 0xffff
		}
		binary.BigEndian.PutUint16(body[6:], c)
	default:
		return nil
	}
	return out
}

// pseudo6 sums the IPv6 pseudo-header for an upper-layer checksum.
func pseudo6(ip []byte, next byte, length int) uint32 {
	var sum uint32
	for i := 8; i < 40; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(ip[i:]))
	}
	sum += uint32(length>>16) + uint32(length&0xffff)
	sum += uint32(next)
	return sum
}
