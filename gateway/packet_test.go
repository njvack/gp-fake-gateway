package gateway

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func ipv4Packet(proto byte, body []byte) []byte {
	p := make([]byte, 20+len(body))
	p[0] = 0x45
	binary.BigEndian.PutUint16(p[2:], uint16(len(p)))
	p[8] = 64
	p[9] = proto
	copy(p[12:16], []byte{10, 99, 0, 2})
	copy(p[16:20], []byte{10, 99, 0, 1})
	binary.BigEndian.PutUint16(p[10:], checksum(0, p[:20]))
	copy(p[20:], body)
	return p
}

func TestICMPv4Echo(t *testing.T) {
	icmp := []byte{8, 0, 0, 0, 0x12, 0x34, 0, 1, 'p', 'i', 'n', 'g'}
	binary.BigEndian.PutUint16(icmp[2:], checksum(0, icmp))
	reply := Respond(ipv4Packet(1, icmp))
	if reply == nil {
		t.Fatal("no reply")
	}
	if checksum(0, reply[:20]) != 0 {
		t.Error("bad IPv4 header checksum")
	}
	if !bytes.Equal(reply[12:16], []byte{10, 99, 0, 1}) || !bytes.Equal(reply[16:20], []byte{10, 99, 0, 2}) {
		t.Errorf("addresses not swapped: %v -> %v", reply[12:16], reply[16:20])
	}
	body := reply[20:]
	if body[0] != 0 {
		t.Errorf("ICMP type = %d, want 0", body[0])
	}
	if checksum(0, body) != 0 {
		t.Error("bad ICMP checksum")
	}
	if !bytes.Equal(body[4:], icmp[4:]) {
		t.Error("id, sequence or payload changed")
	}
}

func TestUDPv4Echo(t *testing.T) {
	udp := []byte{0x30, 0x39, 0, EchoPort, 0, 13, 0, 0, 'h', 'e', 'l', 'l', 'o'}
	reply := Respond(ipv4Packet(17, udp))
	if reply == nil {
		t.Fatal("no reply")
	}
	body := reply[20:]
	if binary.BigEndian.Uint16(body[0:]) != EchoPort || binary.BigEndian.Uint16(body[2:]) != 12345 {
		t.Errorf("ports not swapped: %v", body[:4])
	}
	if string(body[8:]) != "hello" {
		t.Errorf("payload = %q", body[8:])
	}
}

func TestIgnoresOtherTraffic(t *testing.T) {
	udp := []byte{0x30, 0x39, 0, 53, 0, 8, 0, 0}
	if Respond(ipv4Packet(17, udp)) != nil {
		t.Error("answered UDP to a non-echo port")
	}
	if Respond(ipv4Packet(6, make([]byte, 20))) != nil {
		t.Error("answered TCP")
	}
	if Respond([]byte{0x45, 0}) != nil {
		t.Error("answered a truncated packet")
	}
}

func TestICMPv6Echo(t *testing.T) {
	icmp := []byte{128, 0, 0, 0, 0, 7, 0, 1, 'x'}
	p := make([]byte, 40+len(icmp))
	p[0] = 0x60
	binary.BigEndian.PutUint16(p[4:], uint16(len(icmp)))
	p[6] = 58
	p[7] = 64
	p[8], p[23] = 0xfd, 2  // fd00::2
	p[24], p[39] = 0xfd, 1 // fd00::1
	copy(p[40:], icmp)
	binary.BigEndian.PutUint16(p[42:], checksum(pseudo6(p, 58, len(icmp)), p[40:]))

	reply := Respond(p)
	if reply == nil {
		t.Fatal("no reply")
	}
	if reply[40] != 129 {
		t.Errorf("ICMPv6 type = %d, want 129", reply[40])
	}
	if reply[8] != 0xfd || reply[23] != 1 || reply[39] != 2 {
		t.Error("addresses not swapped")
	}
	if checksum(pseudo6(reply, 58, len(icmp)), reply[40:]) != 0 {
		t.Error("bad ICMPv6 checksum")
	}
}

func TestFrameRoundTrip(t *testing.T) {
	for _, f := range []Frame{{}, {EtherType: etherIPv4, Payload: []byte{0x45, 1, 2, 3}}} {
		wire := EncodeFrame(f)
		if f.IsKeepalive() {
			want := []byte{0x1a, 0x2b, 0x3c, 0x4d, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
			if !bytes.Equal(wire, want) {
				t.Errorf("keepalive = %x, want %x", wire, want)
			}
		} else if binary.LittleEndian.Uint32(wire[8:]) != 1 {
			t.Error("data frame missing its 1 marker")
		}
		got, err := ReadFrame(bytes.NewReader(wire))
		if err != nil {
			t.Fatal(err)
		}
		if got.EtherType != f.EtherType || !bytes.Equal(got.Payload, f.Payload) {
			t.Errorf("round trip: got %+v, want %+v", got, f)
		}
	}
	if _, err := ReadFrame(bytes.NewReader(make([]byte, 16))); err != ErrBadMagic {
		t.Errorf("err = %v, want ErrBadMagic", err)
	}
}
