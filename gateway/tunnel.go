package gateway

import (
	"bufio"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
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
	// Set by a scenario rule: stop answering keepalives on this tunnel.
	ignoreKeepalive atomic.Bool
}

type tunnelRulesKey struct{}

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
	rules, _ := r.Context().Value(tunnelRulesKey{}).([]Rule)
	s.serveTunnel(conn, rw.Reader, user, cookie, rules)
}

func (s *Server) serveTunnel(conn net.Conn, br *bufio.Reader, user, cookie string, rules []Rule) {
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

	for _, rule := range rules {
		d := time.Duration(rule.After * float64(time.Second))
		var timer *time.Timer
		switch rule.Do {
		case "drop_tunnel":
			timer = time.AfterFunc(d, func() {
				s.log.Info("scenario: dropping tunnel", "user", user, "after", rule.After)
				t.Close()
			})
		case "ignore_keepalive":
			timer = time.AfterFunc(d, func() {
				s.log.Info("scenario: ignoring keepalives", "user", user, "after", rule.After)
				t.ignoreKeepalive.Store(true)
			})
		}
		if timer != nil {
			defer timer.Stop()
		}
	}

	if _, err := io.WriteString(t, "START_TUNNEL"); err != nil {
		return
	}
	s.log.Info("tunnel up", "user", user)

	rr := recordReader{conn: conn}
	if n := br.Buffered(); n > 0 {
		rr.pending, _ = br.Peek(n)
	}
	stalled := false
	for {
		frames, whole, err := rr.next()
		if err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
				s.log.Info("tunnel read", "user", user, "err", err)
			}
			return
		}
		if !stalled && (!whole || len(frames) > 1) && !s.cfg.get().AllowSharedRecords {
			// What PAN-OS 11.1 did: TCP stays up, the tunnel goes quiet.
			stalled = true
			s.log.Info("tunnel stalled: TLS record without exactly one GPST frame", "user", user, "frames", len(frames), "whole", whole)
			s.sessions.update(cookie, func(ss *Session) { ss.Stalled = true })
		}
		for _, f := range frames {
			if stalled {
				continue
			}
			if f.IsKeepalive() {
				if s.cfg.get().IgnoreKeepalive || t.ignoreKeepalive.Load() {
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
}

// recordReader reads a tunnel one TLS record at a time: crypto/tls returns
// at most one record's plaintext per Read, given a buffer that can hold it.
type recordReader struct {
	conn    net.Conn
	pending []byte // bytes a bufio.Reader held before the tunnel started
	buf     []byte // a partial frame carried over from the last record
	scratch [1 << 16]byte
}

// next reads one record and returns the frames it completes. whole is false
// when the record ends partway through a frame.
func (r *recordReader) next() (frames []Frame, whole bool, err error) {
	var rec []byte
	if r.pending != nil {
		rec, r.pending = append([]byte(nil), r.pending...), nil
	} else {
		n, err := r.conn.Read(r.scratch[:])
		if n == 0 {
			if err == nil {
				err = io.ErrNoProgress
			}
			return nil, false, err
		}
		rec = r.scratch[:n]
	}
	r.buf = append(r.buf, rec...)
	for len(r.buf) >= gpstHeaderLen {
		if binary.BigEndian.Uint32(r.buf[0:]) != gpstMagic {
			return frames, false, ErrBadMagic
		}
		n := int(binary.BigEndian.Uint16(r.buf[6:]))
		if len(r.buf) < gpstHeaderLen+n {
			break
		}
		f := Frame{EtherType: binary.BigEndian.Uint16(r.buf[4:])}
		if n > 0 {
			f.Payload = append([]byte(nil), r.buf[gpstHeaderLen:gpstHeaderLen+n]...)
		}
		frames = append(frames, f)
		r.buf = r.buf[gpstHeaderLen+n:]
	}
	whole = len(r.buf) == 0
	if whole {
		r.buf = nil
	} else {
		r.buf = append([]byte(nil), r.buf...)
	}
	return frames, whole, nil
}
