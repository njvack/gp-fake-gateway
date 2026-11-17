package gateway

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
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
	rules      ruleSet
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
		handled, after, tunnelRules := s.applyRules(w, r)
		defer s.runAfter(after)
		if handled {
			return
		}
		if len(tunnelRules) > 0 {
			r = r.WithContext(context.WithValue(r.Context(), tunnelRulesKey{}, tunnelRules))
		}
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
		license := ""
		if iface == "gateway" {
			license = "\n<license>yes</license>"
		}
		writeXML(w, http.StatusOK, `<?xml version="1.0" encoding="UTF-8" ?>
<prelogin-response>
<status>Success</status>
<ccusername></ccusername>
<autosubmit>false</autosubmit>
<msg></msg>
<newmsg></newmsg>`+license+`
<authentication-message>Enter login credentials for the fake GP `+iface+`</authentication-message>
<username-label>Username</username-label>
<password-label>Password</password-label>
<panos-version>1</panos-version>
<saml-default-browser>yes</saml-default-browser>
<auth-api>no</auth-api><server-ip>`+esc(localHost(r))+`</server-ip><default-browser>no</default-browser><region>US</region>
</prelogin-response>`)
	}
}

// localHost is the address the client connected to.
func localHost(r *http.Request) string {
	if a, ok := r.Context().Value(http.LocalAddrContextKey).(net.Addr); ok {
		if host, _, err := net.SplitHostPort(a.String()); err == nil {
			return host
		}
	}
	return ""
}

func (s *Server) checkPassword(cfg Config, user, passwd string) bool {
	want, ok := cfg.Users[user]
	return ok && user != "" && passwd == want
}

// authenticate runs the password and, if asked for, challenge steps of a
// portal getconfig.esp or gateway login.esp. It returns the user once both
// are done; otherwise it has written the answer (an error or a challenge).
func (s *Server) authenticate(w http.ResponseWriter, r *http.Request, cfg Config, challenge bool, style string) (string, bool) {
	user, passwd, inputStr := r.Form.Get("user"), r.Form.Get("passwd"), r.Form.Get("inputStr")
	if challenge && inputStr != "" {
		// Second step: the answer to a challenge we issued.
		s.mu.Lock()
		want, ok := s.challenges[inputStr]
		delete(s.challenges, inputStr)
		s.mu.Unlock()
		if !ok || want != user || passwd != cfg.SecondFactorAnswer {
			s.log.Info("second factor rejected", "user", user)
			http.Error(w, "Invalid username or password", 512)
			return "", false
		}
		return user, true
	}
	if !s.checkPassword(cfg, user, passwd) {
		s.log.Info("password rejected", "user", user)
		http.Error(w, "Invalid username or password", 512)
		return "", false
	}
	if !challenge {
		return user, true
	}
	token := randomHex(8)
	s.mu.Lock()
	s.challenges[token] = user
	s.mu.Unlock()
	writeChallenge(w, style, user, token, cfg.SecondFactorPrompt)
	return "", false
}

// writeChallenge sends a GP challenge. PAN-OS sends it as XML from the
// portal and, at least in 11.1, as JavaScript in HTML from the gateway.
func writeChallenge(w http.ResponseWriter, style, user, token, prompt string) {
	if style != "javascript" {
		writeXML(w, http.StatusOK, "<challenge>\n<user>"+esc(user)+"</user>\n<inputstr>"+token+
			"</inputstr>\n<respmsg>"+esc(prompt)+"</respmsg>\n</challenge>\n")
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=UTF-8")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "<html>\n  <head></head>\n  <body>\n  var respStatus = \"Challenge\";\n  var respMsg = %s;\n  thisForm.inputStr.value = \"%s\";\n</body>\n</html>\n",
		jsString(prompt), token)
}

// jsString quotes v as a JavaScript string literal. openconnect reads it
// with a JSON parser.
func jsString(v string) string {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	enc.Encode(v)
	return strings.TrimSpace(b.String())
}

func (s *Server) portalConfig(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	cfg := s.cfg.get()
	if _, ok := s.authenticate(w, r, cfg, cfg.SecondFactor == "challenge" && cfg.PortalSecondFactor, "xml"); !ok {
		return
	}
	writeXML(w, http.StatusOK, portalPolicy(r.Host, cfg))
}

// portalPolicy is the portal's getconfig.esp answer, shaped like PAN-OS
// 11.1's: the fields clients read, and a sample of the rest.
func portalPolicy(host string, cfg Config) string {
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8" ?>
<policy>
  <agent-user-override-key>****</agent-user-override-key>
  <portal-name>fake-portal</portal-name>
  <portal-config-version>4100</portal-config-version>
  <version>6.2.8-948</version>
  <client-role>global-protect-full</client-role>
  <gateways>
    <cutoff-time>5</cutoff-time>
    <external>
      <list>
        <entry name="%[1]s">
          <description>Fake gateway</description>
          <priority-rule>
            <entry name="Any">
              <priority>1</priority>
            </entry>
          </priority-rule>
        </entry>
      </list>
    </external>
  </gateways>
  <gateways-v6>
    <cutoff-time>5</cutoff-time>
    <external>
      <list>
        <entry name="Fake gateway">
          <fqdn>%[1]s</fqdn>
          <priority-rule>
            <entry name="Any">
              <priority>1</priority>
            </entry>
          </priority-rule>
        </entry>
      </list>
    </external>
  </gateways-v6>
  <agent-config>
    <save-user-credentials>2</save-user-credentials>
    <portal-2fa>no</portal-2fa>
    <internal-gateway-2fa>no</internal-gateway-2fa>
    <auto-discovery-external-gateway-2fa>no</auto-discovery-external-gateway-2fa>
    <manual-only-gateway-2fa>no</manual-only-gateway-2fa>
    <retry-tunnel>30</retry-tunnel>
    <retry-timeout>5</retry-timeout>
    <tunnel-mtu>1400</tunnel-mtu>
    <portal-timeout>30</portal-timeout>
    <connect-timeout>60</connect-timeout>
    <receive-timeout>30</receive-timeout>
    <split-tunnel-option>network-traffic</split-tunnel-option>
    <enforce-dns>yes</enforce-dns>
    <ipv6-preferred>yes</ipv6-preferred>
  </agent-config>
  <use-sso>yes</use-sso>
  <connect-method>on-demand</connect-method>
  <on-demand>yes</on-demand>
  <refresh-config>yes</refresh-config>
  <refresh-config-interval>24</refresh-config-interval>
  <hip-collection>
    <hip-report-interval>%[2]d</hip-report-interval>
    <max-wait-time>30</max-wait-time>
    <collect-hip-data>yes</collect-hip-data>
    <default>
      <category>
        <member>host-info</member>
        <member>data-loss-prevention</member>
        <member>patch-management</member>
        <member>firewall</member>
        <member>anti-malware</member>
        <member>disk-backup</member>
        <member>disk-encryption</member>
      </category>
    </default>
  </hip-collection>

<portal-userauthcookie>empty</portal-userauthcookie>
<portal-prelogonuserauthcookie>empty</portal-prelogonuserauthcookie>
<config-digest>00000000000000000000000000000000</config-digest>
</policy>`, esc(host), cfg.HIPInterval)
}

func (s *Server) gatewayLogin(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	cfg := s.cfg.get()
	user, ok := s.authenticate(w, r, cfg, cfg.SecondFactor == "challenge", cfg.ChallengeStyle)
	if !ok {
		return
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

	// The 22 arguments PAN-OS 11.1 sends. 15 and 18 are the preferred
	// addresses; 16 and 17 the portal cookies, "empty" as the portal sends
	// them; 19 is openconnect's "usually-equals-4".
	args := []string{
		"", sess.AuthCookie, "PersistentCookie", sess.Portal, sess.User, "Fake-Auth", "vsys1",
		sess.Domain, "", "", "", "", "tunnel", "-1", "4100", sess.IPv4, "empty", "empty", sess.IPv6, "4", "", "",
	}
	var b strings.Builder
	b.WriteString("<?xml version=\"1.0\" encoding=\"UTF-8\" ?>\n<jnlp>\n<application-desc>\n")
	for _, a := range args {
		b.WriteString("<argument>" + esc(a) + "</argument>\n")
	}
	b.WriteString("</application-desc>\n</jnlp>\n")
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

	// Element order and the extra notification fields follow PAN-OS 11.1.
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8" ?>` + "\n")
	b.WriteString(`<response status="success">`)
	b.WriteString("<need-tunnel>yes</need-tunnel>")
	b.WriteString("<ssl-tunnel-url>" + TunnelPath + "</ssl-tunnel-url>")
	b.WriteString("<portal>" + esc(sess.Portal) + "</portal><user>" + esc(sess.User) + "</user>")
	b.WriteString("<quarantine>no</quarantine>")
	remaining := cfg.Lifetime - int(s.now().Sub(sess.Issued).Seconds())
	if cfg.Lifetime > 0 {
		b.WriteString(fmt.Sprintf("<lifetime>%d</lifetime>", max(remaining, 1)))
	}
	if cfg.Rekey > 0 {
		b.WriteString(fmt.Sprintf("<timeout>%d</timeout>", cfg.Rekey))
	}
	b.WriteString("<lifetime-notify-prior>3600</lifetime-notify-prior>")
	b.WriteString("<lifetime-notify-message>Your GlobalProtect session will expire in 30 minutes. Please save your work before your session expires.</lifetime-notify-message>")
	b.WriteString("<inactivity-notify-prior>1800</inactivity-notify-prior>")
	b.WriteString("<inactivity-notify-message>Your GlobalProtect session will time out in 30 minutes. Please save your work before your session times out.</inactivity-notify-message>")
	b.WriteString("<admin-logout-notify-message>Your administrator has logged you out.</admin-logout-notify-message>")
	b.WriteString(fmt.Sprintf("<user_expires>%d</user_expires>", sess.Issued.Add(365*24*time.Hour).Unix()))
	if cfg.IdleTimeout > 0 {
		b.WriteString(fmt.Sprintf("<disconnect-on-idle>%d</disconnect-on-idle>", cfg.IdleTimeout))
	}
	b.WriteString("<bw-c2s>1000</bw-c2s><bw-s2c>1000</bw-s2c>")
	b.WriteString("<panos-version>11.1.13-h16</panos-version>")
	if host := localHost(r); host != "" {
		b.WriteString("<gw-address>" + esc(host) + "</gw-address>")
	}
	ipv6 := "no"
	if sess.IPv6 != "" {
		ipv6 = "yes"
	}
	b.WriteString("<ipv6-connection>" + ipv6 + "</ipv6-connection>")
	b.WriteString("<ip-address>" + esc(sess.IPv4) + "</ip-address><netmask>255.255.255.255</netmask>")
	b.WriteString("<ip-address-preferred>yes</ip-address-preferred>")
	if sess.IPv6 != "" {
		b.WriteString("<ip-address-v6>" + esc(sess.IPv6) + "</ip-address-v6>")
	}
	b.WriteString(members("dns", cfg.DNS))
	b.WriteString("<wins></wins>")
	b.WriteString(members("dns-suffix", cfg.DNSSuffix))
	b.WriteString("<default-gateway>" + esc(sess.IPv4) + "</default-gateway>")
	// PAN-OS 11.1 sends 0 when no MTU is configured; clients then work one out.
	b.WriteString(fmt.Sprintf("<mtu>%d</mtu>", cfg.MTU))
	b.WriteString("<no-direct-access-to-local-network>no</no-direct-access-to-local-network>")
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
	writeXML(w, http.StatusOK, "<response status=\"success\">\n<hip-report-needed>"+yn+
		"</hip-report-needed>\n<delay>0</delay>\n<quarantine>no</quarantine>\n</response>\n")
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
	writeXML(w, http.StatusOK, "<response status=\"success\">\n<notification></notification>\n</response>\n")
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
	writeXML(w, http.StatusOK, `<?xml version="1.0" encoding="UTF-8" ?>`+"\n<response status=\"success\">\n"+
		"<portal>"+esc(r.Form.Get("portal"))+"</portal>\n<user>"+esc(r.Form.Get("user"))+"</user>\n"+
		"<domain>"+esc(r.Form.Get("domain"))+"</domain>\n<computer>"+esc(r.Form.Get("computer"))+"</computer>\n</response>\n")
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
