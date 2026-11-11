package gateway

import (
	"bytes"
	"net"
)

// openconnect sends the tunnel request without a Host header, and net/http
// rejects HTTP/1.1 requests that lack one before any handler runs. The
// hostFixListener's connections insert "Host: gp" after that one request
// line. The request arrives in a single TLS record, so matching within one
// Read is enough. After the tunnel starts the stream is GPST frames, so the
// rewrite stops after its first match.
type hostFixListener struct{ net.Listener }

func (l *hostFixListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &hostFixConn{Conn: c}, nil
}

type hostFixConn struct {
	net.Conn
	done    bool
	pending []byte
}

var tunnelRequestPrefix = []byte("GET " + TunnelPath)

func (c *hostFixConn) Read(p []byte) (int, error) {
	if len(c.pending) > 0 {
		n := copy(p, c.pending)
		c.pending = c.pending[n:]
		return n, nil
	}
	n, err := c.Conn.Read(p)
	if c.done || n == 0 {
		return n, err
	}
	i := bytes.Index(p[:n], tunnelRequestPrefix)
	if i < 0 {
		return n, err
	}
	j := bytes.Index(p[i:n], []byte("\r\n"))
	if j < 0 {
		return n, err
	}
	c.done = true
	at := i + j + 2
	var fixed []byte
	fixed = append(fixed, p[:at]...)
	fixed = append(fixed, "Host: gp\r\n"...)
	fixed = append(fixed, p[at:n]...)
	m := copy(p, fixed)
	c.pending = fixed[m:]
	return m, err
}
