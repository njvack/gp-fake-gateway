package gateway

import (
	"bufio"
	"crypto/tls"
	"encoding/binary"
	"encoding/xml"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

type fixture struct {
	t    *testing.T
	srv  *Server
	addr string
	http *http.Client

	mu  sync.Mutex
	now time.Time
}

func newFixture(t *testing.T, mutate func(*Config)) *fixture {
	t.Helper()
	cfg := DefaultConfig()
	if mutate != nil {
		mutate(&cfg)
	}
	f := &fixture{t: t, now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	f.srv = New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	f.srv.now = func() time.Time {
		f.mu.Lock()
		defer f.mu.Unlock()
		return f.now
	}
	cert, _, err := SelfSignedCert([]string{"127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go f.srv.Serve(ln, &tls.Config{Certificates: []tls.Certificate{cert}})
	f.addr = ln.Addr().String()
	f.http = &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	return f
}

func (f *fixture) advance(d time.Duration) {
	f.mu.Lock()
	f.now = f.now.Add(d)
	f.mu.Unlock()
}

func (f *fixture) post(path string, form url.Values) (int, string) {
	f.t.Helper()
	resp, err := f.http.PostForm("https://"+f.addr+path, form)
	if err != nil {
		f.t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body)
}

// loginForm is the fixed part of what openconnect posts to login.esp.
func loginForm(user, passwd string) url.Values {
	return url.Values{
		"jnlpReady": {"jnlpReady"}, "ok": {"Login"}, "direct": {"yes"}, "clientVer": {"4100"},
		"prot": {"https:"}, "clientos": {"Mac"}, "os-version": {"Apple Mac OS X 27.0"},
		"server": {"127.0.0.1"}, "computer": {"testmac"}, "user": {user}, "passwd": {passwd},
	}
}

// login runs the two-step login and returns the authcookie.
func (f *fixture) login(user, passwd, answer string) string {
	f.t.Helper()
	code, body := f.post("/ssl-vpn/login.esp", loginForm(user, passwd))
	if code != 200 {
		f.t.Fatalf("login step 1: %d %s", code, body)
	}
	var ch struct {
		InputStr string `xml:"inputstr"`
	}
	if err := xml.Unmarshal([]byte(body), &ch); err != nil || ch.InputStr == "" {
		f.t.Fatalf("expected a challenge, got %s", body)
	}
	form := loginForm(user, answer)
	form.Set("inputStr", ch.InputStr)
	code, body = f.post("/ssl-vpn/login.esp", form)
	if code != 200 {
		f.t.Fatalf("login step 2: %d %s", code, body)
	}
	var jnlp struct {
		Args []string `xml:"application-desc>argument"`
	}
	if err := xml.Unmarshal([]byte(body), &jnlp); err != nil || len(jnlp.Args) < 2 {
		f.t.Fatalf("bad jnlp: %s", body)
	}
	return jnlp.Args[1]
}

func TestLoginWithPushChallenge(t *testing.T) {
	f := newFixture(t, nil)
	cookie := f.login("test", "test", "1")
	if len(cookie) != 32 {
		t.Errorf("cookie = %q", cookie)
	}
	if n := len(f.srv.Sessions()); n != 1 {
		t.Errorf("%d sessions, want 1", n)
	}
}

func TestLoginRejections(t *testing.T) {
	f := newFixture(t, nil)
	if code, _ := f.post("/ssl-vpn/login.esp", loginForm("test", "wrong")); code != 512 {
		t.Errorf("bad password: status %d, want 512", code)
	}
	_, body := f.post("/ssl-vpn/login.esp", loginForm("test", "test"))
	var ch struct {
		InputStr string `xml:"inputstr"`
	}
	xml.Unmarshal([]byte(body), &ch)
	form := loginForm("test", "2")
	form.Set("inputStr", ch.InputStr)
	if code, _ := f.post("/ssl-vpn/login.esp", form); code != 512 {
		t.Errorf("wrong second factor: status %d, want 512", code)
	}
	form.Set("passwd", "1") // the challenge is single-use
	if code, _ := f.post("/ssl-vpn/login.esp", form); code != 512 {
		t.Errorf("reused challenge: status %d, want 512", code)
	}
}

func TestGetconfig(t *testing.T) {
	f := newFixture(t, func(c *Config) { c.Rekey = 3600; c.NewIPOnReconnect = true })
	cookie := f.login("test", "test", "1")
	form := url.Values{"user": {"test"}, "authcookie": {cookie}}
	_, body := f.post("/ssl-vpn/getconfig.esp", form)
	for _, want := range []string{
		"<ip-address>10.99.0.2</ip-address>", "<member>10.99.0.0/24</member>",
		"<member>10.99.0.53</member>", "<timeout>3600</timeout>", "<lifetime>86400</lifetime>",
		"<ssl-tunnel-url>/ssl-tunnel-connect.sslvpn</ssl-tunnel-url>",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("getconfig missing %s:\n%s", want, body)
		}
	}
	_, body = f.post("/ssl-vpn/getconfig.esp", form)
	if !strings.Contains(body, "<ip-address>10.99.0.3</ip-address>") {
		t.Errorf("second getconfig should hand out a new IP:\n%s", body)
	}
	_, body = f.post("/ssl-vpn/getconfig.esp", url.Values{"user": {"test"}, "authcookie": {"nope"}})
	if !strings.Contains(body, invalidCookie) {
		t.Errorf("bad cookie: %s", body)
	}
}

func TestHIPCheckAndReport(t *testing.T) {
	f := newFixture(t, func(c *Config) { c.HIPNeeded = true })
	cookie := f.login("test", "test", "1")
	form := url.Values{"user": {"test"}, "authcookie": {cookie}, "md5": {"abc"}}
	if _, body := f.post("/ssl-vpn/hipreportcheck.esp", form); !strings.Contains(body, "<hip-report-needed>yes<") {
		t.Fatalf("first check: %s", body)
	}
	rep := url.Values{"user": {"test"}, "authcookie": {cookie}, "md5": {"abc"}, "report": {"<hip-report/>"}}
	if _, body := f.post("/ssl-vpn/hipreport.esp", rep); !strings.Contains(body, `status="success"`) {
		t.Fatalf("report: %s", body)
	}
	if _, body := f.post("/ssl-vpn/hipreportcheck.esp", form); !strings.Contains(body, "<hip-report-needed>no<") {
		t.Errorf("check after report: %s", body)
	}
	if got := f.srv.Sessions()[0].HIPReports; len(got) != 1 || got[0].Report != "<hip-report/>" {
		t.Errorf("stored reports = %+v", got)
	}
	f.srv.cfg.merge([]byte(`{"hip_check_fail": true}`))
	if code, _ := f.post("/ssl-vpn/hipreportcheck.esp", form); code != 500 {
		t.Errorf("injected failure: status %d, want 500", code)
	}
}

// openTunnel does what openconnect does: one POST on a fresh TLS connection,
// then the tunnel GET on the same connection, with no Host header.
func (f *fixture) openTunnel(cookie string) (*tls.Conn, *bufio.Reader, string) {
	f.t.Helper()
	conn, err := tls.Dial("tcp", f.addr, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		f.t.Fatal(err)
	}
	f.t.Cleanup(func() { conn.Close() })
	br := bufio.NewReader(conn)
	body := "user=test&authcookie=" + cookie
	io.WriteString(conn, "POST /ssl-vpn/hipreportcheck.esp HTTP/1.1\r\nHost: x\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: "+
		strconv.Itoa(len(body))+"\r\n\r\n"+body)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		f.t.Fatal(err)
	}
	io.ReadAll(resp.Body)
	resp.Body.Close()

	io.WriteString(conn, "GET "+TunnelPath+"?user=test&authcookie="+cookie+" HTTP/1.1\r\n\r\n")
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	head := make([]byte, 12)
	n, _ := io.ReadFull(br, head)
	return conn, br, string(head[:n])
}

func TestTunnel(t *testing.T) {
	f := newFixture(t, nil)
	cookie := f.login("test", "test", "1")
	conn, br, head := f.openTunnel(cookie)
	if head != "START_TUNNEL" {
		t.Fatalf("tunnel start = %q", head)
	}

	conn.Write(EncodeFrame(Frame{}))
	got, err := ReadFrame(br)
	if err != nil || !got.IsKeepalive() {
		t.Fatalf("keepalive reply = %+v, %v", got, err)
	}

	icmp := []byte{8, 0, 0, 0, 0, 1, 0, 1}
	binary.BigEndian.PutUint16(icmp[2:], checksum(0, icmp))
	conn.Write(EncodeFrame(Frame{EtherType: etherIPv4, Payload: ipv4Packet(1, icmp)}))
	got, err = ReadFrame(br)
	if err != nil || got.EtherType != etherIPv4 || got.Payload[20] != 0 {
		t.Fatalf("echo reply = %+v, %v", got, err)
	}

	s := f.srv.Sessions()[0]
	if !s.TunnelUp || s.Tunnels != 1 || s.Keepalives != 1 || s.PacketsIn != 1 || s.PacketsOut != 1 {
		t.Errorf("session counters = %+v", s)
	}

	if n := f.srv.DropTunnels(); n != 1 {
		t.Errorf("dropped %d tunnels, want 1", n)
	}
	if _, err := ReadFrame(br); err == nil {
		t.Error("tunnel still readable after drop")
	}
	// The session survives a dropped tunnel, so the client can reconnect.
	if _, _, head := f.openTunnel(cookie); head != "START_TUNNEL" {
		t.Errorf("reconnect after drop = %q", head)
	}
}

func TestCookieExpiry(t *testing.T) {
	f := newFixture(t, func(c *Config) { c.Lifetime = 600; c.IdleTimeout = 0 })

	// Lifetime: valid just before, rejected just after.
	cookie := f.login("test", "test", "1")
	f.advance(590 * time.Second)
	if _, _, head := f.openTunnel(cookie); head != "START_TUNNEL" {
		t.Fatalf("before lifetime: %q", head)
	}
	f.srv.DropTunnels()
	time.Sleep(50 * time.Millisecond) // let the server mark the tunnel down
	f.advance(20 * time.Second)
	if _, _, head := f.openTunnel(cookie); !strings.HasPrefix(head, "HTTP/1.1 502") {
		t.Errorf("after lifetime: %q, want a 502", head)
	}

	// Idle timeout: no tunnel for longer than IdleTimeout kills the cookie.
	f.srv.cfg.merge([]byte(`{"idle_timeout": 60}`))
	cookie = f.login("test", "test", "1")
	f.advance(61 * time.Second)
	if _, _, head := f.openTunnel(cookie); !strings.HasPrefix(head, "HTTP/1.1 502") {
		t.Errorf("after idle timeout: %q, want a 502", head)
	}

	// Explicit expiry from the control API.
	cookie = f.login("test", "test", "1")
	f.srv.ExpireSessions("test")
	if _, _, head := f.openTunnel(cookie); !strings.HasPrefix(head, "HTTP/1.1 502") {
		t.Errorf("after ExpireSessions: %q, want a 502", head)
	}
}

func TestLogout(t *testing.T) {
	f := newFixture(t, nil)
	cookie := f.login("test", "test", "1")
	_, br, head := f.openTunnel(cookie)
	if head != "START_TUNNEL" {
		t.Fatal(head)
	}
	if _, body := f.post("/ssl-vpn/logout.esp", url.Values{"user": {"test"}, "authcookie": {cookie}}); !strings.Contains(body, "success") {
		t.Errorf("logout: %s", body)
	}
	if _, err := ReadFrame(br); err == nil {
		t.Error("tunnel survived logout")
	}
	if _, _, head := f.openTunnel(cookie); !strings.HasPrefix(head, "HTTP/1.1 502") {
		t.Errorf("tunnel after logout: %q", head)
	}
}
