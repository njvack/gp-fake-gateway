package gateway

import (
	"crypto/tls"
	"encoding/xml"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// TunnelPath is where openconnect opens the HTTPS tunnel. It is sent in
// getconfig.esp as ssl-tunnel-url.
const TunnelPath = "/ssl-tunnel-connect.sslvpn"

// Server is a fake GlobalProtect portal and gateway on one TLS listener.
type Server struct {
	cfg      configStore
	sessions *sessionStore
	log      *slog.Logger
	now      func() time.Time

	mu         sync.Mutex
	challenges map[string]string // inputStr -> user
	tunnels    map[*tunnelConn]struct{}
}

// New returns a server using cfg.
func New(cfg Config, log *slog.Logger) *Server {
	if log == nil {
		log = slog.Default()
	}
	s := &Server{
		log:        log,
		now:        time.Now,
		challenges: map[string]string{},
		tunnels:    map[*tunnelConn]struct{}{},
	}
	s.cfg.set(cfg)
	s.sessions = newSessionStore(func() time.Time { return s.now() })
	return s
}

// Config returns the current configuration.
func (s *Server) Config() Config { return s.cfg.get() }

// Sessions returns a snapshot of every session.
func (s *Server) Sessions() []Session { return s.sessions.snapshot(s.cfg.get()) }

// Serve accepts TLS connections on ln and serves the portal, the gateway and
// the HTTPS tunnel on them. It returns when ln is closed.
func (s *Server) Serve(ln net.Listener, tlsConfig *tls.Config) error {
	hs := &http.Server{
		Handler:  s.httpHandler(),
		ErrorLog: slog.NewLogLogger(s.log.Handler(), slog.LevelDebug),
	}
	return hs.Serve(&hostFixListener{tls.NewListener(ln, tlsConfig)})
}

func (s *Server) httpHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/global-protect/prelogin.esp", s.prelogin("portal"))
	mux.HandleFunc("/ssl-vpn/prelogin.esp", s.prelogin("gateway"))
	mux.HandleFunc("POST /global-protect/getconfig.esp", s.portalConfig)
	mux.HandleFunc("POST /ssl-vpn/login.esp", s.gatewayLogin)
	mux.HandleFunc("POST /ssl-vpn/getconfig.esp", s.gatewayConfig)
	mux.HandleFunc("POST /ssl-vpn/hipreportcheck.esp", s.hipCheck)
	mux.HandleFunc("POST /ssl-vpn/hipreport.esp", s.hipReport)
	mux.HandleFunc("POST /ssl-vpn/logout.esp", s.logout)
	mux.HandleFunc("GET "+TunnelPath, s.tunnel)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if d := s.cfg.get().StallSeconds; d > 0 {
			time.Sleep(time.Duration(d) * time.Second)
		}
		s.log.Info("request", "method", r.Method, "path", r.URL.Path)
		mux.ServeHTTP(w, r)
	})
}

func esc(v string) string {
	var b strings.Builder
	xml.EscapeText(&b, []byte(v))
	return b.String()
}

func writeXML(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "application/xml; charset=UTF-8")
	w.WriteHeader(status)
	fmt.Fprint(w, body)
}

func writeGPError(w http.ResponseWriter, msg string) {
	writeXML(w, http.StatusOK, `<response status="error"><error>`+esc(msg)+`</error></response>`)
}

// invalidCookie is the GP error openconnect maps to "cookie rejected".
const invalidCookie = "Invalid authentication cookie"

func (s *Server) prelogin(iface string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeXML(w, http.StatusOK, `<?xml version="1.0" encoding="UTF-8" ?>
<prelogin-response>
<status>Success</status>
<ccusername/>
<autosubmit>false</autosubmit>
<msg/>
<newmsg/>
<authentication-message>Enter login credentials for the fake GP `+iface+`</authentication-message>
<username-label>Username</username-label>
<password-label>Password</password-label>
<panos-version>1</panos-version>
<region>US</region>
</prelogin-response>`)
	}
}

func (s *Server) checkPassword(cfg Config, user, passwd string) bool {
	want, ok := cfg.Users[user]
	return ok && user != "" && passwd == want
}

func (s *Server) portalConfig(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	cfg := s.cfg.get()
	if !s.checkPassword(cfg, r.Form.Get("user"), r.Form.Get("passwd")) {
		http.Error(w, "Invalid username or password", 512)
		return
	}
	writeXML(w, http.StatusOK, fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8" ?>
<policy><version>6.2.8-1045</version>
<gateways><external><list>
<entry name="%s"><description>Fake gateway</description></entry>
</list></external></gateways>
<hip-collection><hip-report-interval>%d</hip-report-interval></hip-collection>
</policy>`, esc(r.Host), cfg.HIPInterval))
}

func (s *Server) gatewayLogin(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	cfg := s.cfg.get()
	user, passwd, inputStr := r.Form.Get("user"), r.Form.Get("passwd"), r.Form.Get("inputStr")

	if cfg.SecondFactor == "challenge" && inputStr != "" {
		// Second step: the answer to a challenge we issued.
		s.mu.Lock()
		want, ok := s.challenges[inputStr]
		delete(s.challenges, inputStr)
		s.mu.Unlock()
		if !ok || want != user || passwd != cfg.SecondFactorAnswer {
			s.log.Info("second factor rejected", "user", user)
			http.Error(w, "Invalid username or password", 512)
			return
		}
	} else {
		if !s.checkPassword(cfg, user, passwd) {
			s.log.Info("password rejected", "user", user)
			http.Error(w, "Invalid username or password", 512)
			return
		}
		if cfg.SecondFactor == "challenge" {
			token := randomHex(8)
			s.mu.Lock()
			s.challenges[token] = user
			s.mu.Unlock()
			writeXML(w, http.StatusOK, `<challenge><user>`+esc(user)+`</user><inputstr>`+token+
				`</inputstr><respmsg>`+esc(cfg.SecondFactorPrompt)+`</respmsg></challenge>`)
			return
		}
	}

	for k, v := range map[string]string{"jnlpReady": "jnlpReady", "ok": "Login", "direct": "yes", "clientVer": "4100", "prot": "https:"} {
		if r.Form.Get(k) != v {
			http.Error(w, "missing or unexpected login field "+k, http.StatusInternalServerError)
			return
		}
	}

	sess := &Session{User: user, Portal: "fake-portal", Domain: "fake-domain", Computer: r.Form.Get("computer")}
	sess.IPv4 = cfg.ClientIPv4
	if r.Form.Get("ipv6-support") == "yes" {
		sess.IPv6 = cfg.ClientIPv6
	}
	s.sessions.create(sess)
	s.log.Info("login", "user", user, "computer", sess.Computer)

	args := []string{
		"(null)", sess.AuthCookie, "PersistentCookie", sess.Portal, sess.User, "Fake-Auth", "vsys1",
		sess.Domain, "(null)", "", "", "", "tunnel", "-1", "4100", sess.IPv4, "", "", sess.IPv6,
	}
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="utf-8"?><jnlp><application-desc>`)
	for _, a := range args {
		b.WriteString("<argument>" + esc(a) + "</argument>")
	}
	b.WriteString("</application-desc></jnlp>")
	writeXML(w, http.StatusOK, b.String())
}

// nextIPv4 returns ip with its last octet advanced by n, wrapping within
// 2..254.
func nextIPv4(ip string, n int) string {
	a, err := netip.ParseAddr(ip)
	if err != nil || !a.Is4() {
		return ip
	}
	b := a.As4()
	b[3] = byte(2 + (int(b[3])-2+n)%253)
	return netip.AddrFrom4(b).String()
}

func members(tag string, vals []string) string {
	if len(vals) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("<" + tag + ">")
	for _, v := range vals {
		b.WriteString("<member>" + esc(v) + "</member>")
	}
	b.WriteString("</" + tag + ">")
	return b.String()
}

func (s *Server) gatewayConfig(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	cfg := s.cfg.get()
	var sess Session
	ok := s.sessions.use(r.Form.Get("authcookie"), r.Form.Get("user"), cfg, func(ss *Session) {
		if cfg.NewIPOnReconnect && ss.Configs > 0 {
			ss.IPv4 = nextIPv4(ss.IPv4, 1)
		}
		ss.Configs++
		sess = *ss
	})
	if !ok {
		writeGPError(w, invalidCookie)
		return
	}

	var b strings.Builder
	b.WriteString("<response>")
	b.WriteString("<need-tunnel>yes</need-tunnel>")
	b.WriteString("<ssl-tunnel-url>" + TunnelPath + "</ssl-tunnel-url>")
	b.WriteString("<portal>" + esc(sess.Portal) + "</portal><user>" + esc(sess.User) + "</user>")
	remaining := cfg.Lifetime - int(s.now().Sub(sess.Issued).Seconds())
	if cfg.Lifetime > 0 {
		b.WriteString(fmt.Sprintf("<lifetime>%d</lifetime>", max(remaining, 1)))
	}
	if cfg.Rekey > 0 {
		b.WriteString(fmt.Sprintf("<timeout>%d</timeout>", cfg.Rekey))
	}
	if cfg.IdleTimeout > 0 {
		b.WriteString(fmt.Sprintf("<disconnect-on-idle>%d</disconnect-on-idle>", cfg.IdleTimeout))
	}
	b.WriteString("<bw-c2s>1000</bw-c2s><bw-s2c>1000</bw-s2c>")
	b.WriteString("<ip-address>" + esc(sess.IPv4) + "</ip-address><netmask>255.255.255.255</netmask>")
	if sess.IPv6 != "" {
		b.WriteString("<ip-address-v6>" + esc(sess.IPv6) + "</ip-address-v6>")
	}
	b.WriteString(members("dns", cfg.DNS))
	b.WriteString(members("dns-suffix", cfg.DNSSuffix))
	if cfg.MTU > 0 {
		b.WriteString(fmt.Sprintf("<mtu>%d</mtu>", cfg.MTU))
	}
	var v4, v6, x4, x6 []string
	for _, rt := range cfg.AccessRoutes {
		if strings.Contains(rt, ":") {
			v6 = append(v6, rt)
		} else {
			v4 = append(v4, rt)
		}
	}
	for _, rt := range cfg.ExcludeRoutes {
		if strings.Contains(rt, ":") {
			x6 = append(x6, rt)
		} else {
			x4 = append(x4, rt)
		}
	}
	b.WriteString(members("access-routes", v4))
	b.WriteString(members("access-routes-v6", v6))
	b.WriteString(members("exclude-access-routes", x4))
	b.WriteString(members("exclude-access-routes-v6", x6))
	if host, _, err := net.SplitHostPort(r.Context().Value(http.LocalAddrContextKey).(net.Addr).String()); err == nil {
		b.WriteString("<gw-address>" + esc(host) + "</gw-address>")
	}
	b.WriteString("</response>")
	writeXML(w, http.StatusOK, b.String())
}

func (s *Server) hipCheck(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	cfg := s.cfg.get()
	if cfg.HIPCheckFail {
		http.Error(w, "HIP check failure (injected)", http.StatusInternalServerError)
		return
	}
	md5 := r.Form.Get("md5")
	needed := false
	ok := s.sessions.use(r.Form.Get("authcookie"), r.Form.Get("user"), cfg, func(ss *Session) {
		ss.HIPChecks++
		if cfg.HIPNeeded {
			needed = true
			for _, rep := range ss.HIPReports {
				if rep.MD5 == md5 {
					needed = false
				}
			}
		}
	})
	if !ok {
		writeGPError(w, invalidCookie)
		return
	}
	yn := "no"
	if needed {
		yn = "yes"
	}
	writeXML(w, http.StatusOK, `<response status="success"><hip-report-needed>`+yn+`</hip-report-needed></response>`)
}

func (s *Server) hipReport(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	cfg := s.cfg.get()
	rep := HIPReport{Received: s.now(), MD5: reportMD5(r.Form.Get("report")), Report: r.Form.Get("report")}
	if rep.MD5 == "" {
		rep.MD5 = r.Form.Get("md5")
	}
	ok := s.sessions.use(r.Form.Get("authcookie"), r.Form.Get("user"), cfg, func(ss *Session) {
		ss.HIPReports = append(ss.HIPReports, rep)
	})
	if !ok {
		writeGPError(w, invalidCookie)
		return
	}
	s.log.Info("hip report", "user", r.Form.Get("user"), "bytes", len(rep.Report))
	writeXML(w, http.StatusOK, `<response status="success"/>`)
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	cookie := r.Form.Get("authcookie")
	found := false
	s.sessions.update(cookie, func(ss *Session) {
		ss.LoggedOut = true
		found = true
	})
	s.closeTunnels(cookie)
	if !found {
		writeGPError(w, invalidCookie)
		return
	}
	s.log.Info("logout", "user", r.Form.Get("user"))
	writeXML(w, http.StatusOK, `<response status="success"/>`)
}

// ExpireSessions marks sessions expired (all, or one user's) and closes their
// tunnels. It returns how many were newly expired.
func (s *Server) ExpireSessions(user string) int {
	n := s.sessions.expire(user)
	s.mu.Lock()
	var victims []*tunnelConn
	for t := range s.tunnels {
		if user == "" || t.user == user {
			victims = append(victims, t)
		}
	}
	s.mu.Unlock()
	for _, t := range victims {
		t.Close()
	}
	return n
}

// DropTunnels closes every open tunnel without touching sessions, as a
// network failure would. It returns how many were closed.
func (s *Server) DropTunnels() int { return s.closeTunnels("") }

func (s *Server) closeTunnels(cookie string) int {
	s.mu.Lock()
	var victims []*tunnelConn
	for t := range s.tunnels {
		if cookie == "" || t.cookie == cookie {
			victims = append(victims, t)
		}
	}
	s.mu.Unlock()
	for _, t := range victims {
		t.Close()
	}
	return len(victims)
}

// reportMD5 is the report's <md5-sum>. openconnect sends the md5 only to
// hipreportcheck.esp; hipreport.esp carries it inside the report.
func reportMD5(report string) string {
	var doc struct {
		MD5 string `xml:"md5-sum"`
	}
	if xml.Unmarshal([]byte(report), &doc) != nil {
		return ""
	}
	return strings.TrimSpace(doc.MD5)
}
