package gateway

import (
	"bufio"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
	"time"
)

// GPST framing: every packet on the HTTPS tunnel has a 16-byte header.
//
//	0..3   magic 0x1a2b3c4d (big-endian)
//	4..5   ethertype: 0x0800 IPv4, 0x86DD IPv6, 0 for keepalive (big-endian)
//	6..7   payload length (big-endian)
//	8..11  1 for data, 0 for keepalive (little-endian)
//	12..15 zero
const (
	gpstMagic     = 0x1a2b3c4d
	gpstHeaderLen = 16
	etherIPv4     = 0x0800
	etherIPv6     = 0x86DD
)

// Frame is one decoded GPST packet.
type Frame struct {
	EtherType uint16
	Payload   []byte
}

// IsKeepalive reports whether f is a DPD/keepalive frame.
func (f Frame) IsKeepalive() bool { return f.EtherType == 0 && len(f.Payload) == 0 }

// EncodeFrame returns the wire form of f.
func EncodeFrame(f Frame) []byte {
	b := make([]byte, gpstHeaderLen+len(f.Payload))
	binary.BigEndian.PutUint32(b[0:], gpstMagic)
	binary.BigEndian.PutUint16(b[4:], f.EtherType)
	binary.BigEndian.PutUint16(b[6:], uint16(len(f.Payload)))
	if !f.IsKeepalive() {
		binary.LittleEndian.PutUint32(b[8:], 1)
	}
	copy(b[gpstHeaderLen:], f.Payload)
	return b
}

// ErrBadMagic means the stream is not GPST.
var ErrBadMagic = errors.New("gpst: bad magic")

// ReadFrame reads one GPST frame from r.
func ReadFrame(r io.Reader) (Frame, error) {
	var hdr [gpstHeaderLen]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return Frame{}, err
	}
	if binary.BigEndian.Uint32(hdr[0:]) != gpstMagic {
		return Frame{}, ErrBadMagic
	}
	f := Frame{EtherType: binary.BigEndian.Uint16(hdr[4:])}
	n := binary.BigEndian.Uint16(hdr[6:])
	if n > 0 {
		f.Payload = make([]byte, n)
		if _, err := io.ReadFull(r, f.Payload); err != nil {
			return Frame{}, err
		}
	}
	return f, nil
}

// tunnelConn is one live HTTPS tunnel.
type tunnelConn struct {
	net.Conn
	user, cookie string
	closeOnce    sync.Once
}

func (t *tunnelConn) Close() error {
	var err error
	t.closeOnce.Do(func() { err = t.Conn.Close() })
	return err
}

// tunnel handles the GET that turns an HTTPS connection into a GPST tunnel.
func (s *Server) tunnel(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	user, cookie := q.Get("user"), q.Get("authcookie")
	if !s.sessions.use(cookie, user, s.cfg.get(), nil) {
		// Real gateways answer a bad cookie here with 502, which openconnect
		// treats as "cookie rejected".
		s.log.Info("tunnel rejected", "user", user)
		w.WriteHeader(http.StatusBadGateway)
		return
	}
	conn, rw, err := http.NewResponseController(w).Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.serveTunnel(conn, rw.Reader, user, cookie)
}

func (s *Server) serveTunnel(conn net.Conn, br *bufio.Reader, user, cookie string) {
	defer conn.Close()
	cfg := s.cfg.get()

	if !s.sessions.use(cookie, user, cfg, func(ss *Session) {
		ss.Tunnels++
		ss.TunnelUp = true
	}) {
		return
	}

	t := &tunnelConn{Conn: conn, user: user, cookie: cookie}
	s.mu.Lock()
	s.tunnels[t] = struct{}{}
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.tunnels, t)
		s.mu.Unlock()
		s.sessions.update(cookie, func(ss *Session) {
			ss.TunnelUp = false
			ss.LastSeen = s.now()
		})
		t.Close()
		s.log.Info("tunnel closed", "user", user)
	}()

	if cfg.DropTunnelAfter > 0 {
		timer := time.AfterFunc(time.Duration(cfg.DropTunnelAfter)*time.Second, func() {
			s.log.Info("dropping tunnel (injected)", "user", user)
			t.Close()
		})
		defer timer.Stop()
	}

	if _, err := io.WriteString(t, "START_TUNNEL"); err != nil {
		return
	}
	s.log.Info("tunnel up", "user", user)

	for {
		f, err := ReadFrame(br)
		if err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
				s.log.Info("tunnel read", "user", user, "err", err)
			}
			return
		}
		if f.IsKeepalive() {
			if s.cfg.get().IgnoreKeepalive {
				continue
			}
			s.sessions.update(cookie, func(ss *Session) { ss.Keepalives++ })
			if _, err := t.Write(EncodeFrame(Frame{})); err != nil {
				return
			}
			continue
		}
		s.sessions.update(cookie, func(ss *Session) { ss.PacketsIn++ })
		reply := Respond(f.Payload)
		if reply == nil {
			continue
		}
		et := uint16(etherIPv4)
		if reply[0]>>4 == 6 {
			et = etherIPv6
		}
		if _, err := t.Write(EncodeFrame(Frame{EtherType: et, Payload: reply})); err != nil {
			return
		}
		s.sessions.update(cookie, func(ss *Session) { ss.PacketsOut++ })
	}
}
