package gateway

import (
	"embed"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path"
	"sort"
	"strings"
	"sync"
	"time"
)

// A Scenario reproduces one gateway behaviour, usually one seen in an Albi
// incident file: a base profile, config overrides, and rules that fire on
// what the client does. albi-diag drafts one from an incident file.
//
//	{
//	  "name": "tunnel refused after a drop",
//	  "issue": "njvack/albi#12",
//	  "profile": "default",
//	  "transport": "https",
//	  "config": {"rekey": 7200},
//	  "rules": [
//	    {"when": {"request": "tunnel", "nth": 1}, "after": 30, "do": "drop_tunnel"},
//	    {"when": {"request": "tunnel", "from": 2, "to": 4}, "respond": {"status": 503}}
//	  ],
//	  "expect": {"connected_within": 60}
//	}
//
// Fields starting with "_" are notes and are ignored.
type Scenario struct {
	Name      string          `json:"name"`
	Issue     string          `json:"issue,omitempty"`
	Profile   string          `json:"profile,omitempty"`
	Transport string          `json:"transport,omitempty"`
	Config    json.RawMessage `json:"config,omitempty"`
	Rules     []Rule          `json:"rules,omitempty"`
	Expect    Expect          `json:"expect"`
}

// A Profile is the baseline behaviour of one kind of gateway: a config and
// rules that apply to every scenario built on it. Profiles live in
// gateway/profiles/NAME.json and are compiled in.
type Profile struct {
	Description string          `json:"description"`
	Config      json.RawMessage `json:"config,omitempty"`
	Rules       []Rule          `json:"rules,omitempty"`
}

// Expect is what the client under test must do. Test scripts read it; the
// gateway does not.
type Expect struct {
	// ConnectedWithin: seconds after the scenario's faults by which the
	// client must have a working tunnel again.
	ConnectedWithin int `json:"connected_within,omitempty"`
	// ExitCode, if set: the client is expected to give up with this status.
	ExitCode *int `json:"exit_code,omitempty"`
}

// A Rule changes how the gateway answers one kind of request.
type Rule struct {
	When When `json:"when"`
	// Respond replaces the answer. For "tunnel", only the status is used and
	// the tunnel is refused.
	Respond *Response `json:"respond,omitempty"`
	// Delay waits this many seconds before answering.
	Delay float64 `json:"delay,omitempty"`
	// Do is an action: "close" (drop the connection without an answer),
	// "drop_tunnels", "expire_sessions" (after answering), or for a tunnel,
	// "drop_tunnel" or "ignore_keepalive" (After seconds into it).
	Do    string  `json:"do,omitempty"`
	After float64 `json:"after,omitempty"`
}

// When picks requests by kind and by their 1-based count since the gateway
// started. Nth picks one; From and To a range (To 0 means no end); neither
// picks every one.
type When struct {
	Request string `json:"request"`
	Nth     int    `json:"nth,omitempty"`
	From    int    `json:"from,omitempty"`
	To      int    `json:"to,omitempty"`
}

// Response is a replacement HTTP answer.
type Response struct {
	Status int     `json:"status"`
	Body   *string `json:"body,omitempty"`
}

func (w When) matches(kind string, n int) bool {
	if w.Request != kind {
		return false
	}
	switch {
	case w.Nth > 0:
		return n == w.Nth
	case w.From > 0 || w.To > 0:
		return n >= w.From && (w.To == 0 || n <= w.To)
	default:
		return true
	}
}

// RequestKinds are the names rules use, by path.
var RequestKinds = map[string]string{
	"/global-protect/prelogin.esp":  "portal-prelogin",
	"/global-protect/getconfig.esp": "portal-getconfig",
	"/ssl-vpn/prelogin.esp":         "prelogin",
	"/ssl-vpn/login.esp":            "login",
	"/ssl-vpn/getconfig.esp":        "getconfig",
	"/ssl-vpn/hipreportcheck.esp":   "hipreportcheck",
	"/ssl-vpn/hipreport.esp":        "hipreport",
	"/ssl-vpn/logout.esp":           "logout",
	TunnelPath:                      "tunnel",
}

var validActions = map[string]bool{
	"": true, "close": true, "drop_tunnels": true, "expire_sessions": true,
	"drop_tunnel": true, "ignore_keepalive": true,
}

//go:embed profiles/*.json
var profileFS embed.FS

// Profiles lists the compiled-in profile names.
func Profiles() []string {
	entries, _ := profileFS.ReadDir("profiles")
	var names []string
	for _, e := range entries {
		names = append(names, strings.TrimSuffix(e.Name(), ".json"))
	}
	sort.Strings(names)
	return names
}

// LoadProfile returns a compiled-in profile.
func LoadProfile(name string) (Profile, error) {
	if name == "" {
		name = "default"
	}
	data, err := profileFS.ReadFile(path.Join("profiles", name+".json"))
	if err != nil {
		return Profile{}, fmt.Errorf("no profile %q (have %s)", name, strings.Join(Profiles(), ", "))
	}
	var p Profile
	if err := json.Unmarshal(data, &p); err != nil {
		return Profile{}, fmt.Errorf("profile %s: %w", name, err)
	}
	return p, nil
}

// LoadScenario reads a scenario file.
func LoadScenario(file string) (Scenario, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return Scenario{}, err
	}
	return ParseScenario(data)
}

// ParseScenario parses and checks a scenario.
func ParseScenario(data []byte) (Scenario, error) {
	var sc Scenario
	if err := json.Unmarshal(data, &sc); err != nil {
		return sc, err
	}
	if sc.Transport != "" && sc.Transport != "https" {
		return sc, fmt.Errorf("transport %q is not supported (the fake speaks only the HTTPS tunnel)", sc.Transport)
	}
	for i, r := range sc.Rules {
		if err := r.check(); err != nil {
			return sc, fmt.Errorf("rule %d: %w", i+1, err)
		}
	}
	return sc, nil
}

func (r Rule) check() error {
	known := false
	for _, k := range RequestKinds {
		known = known || k == r.When.Request
	}
	if !known {
		return fmt.Errorf("unknown request %q", r.When.Request)
	}
	if !validActions[r.Do] {
		return fmt.Errorf("unknown action %q", r.Do)
	}
	if (r.Do == "drop_tunnel" || r.Do == "ignore_keepalive") && r.When.Request != "tunnel" {
		return fmt.Errorf("%s only applies to tunnel requests", r.Do)
	}
	return nil
}

// Apply returns cfg with the scenario's profile and overrides merged over it,
// and the rules to run: the profile's first, then the scenario's.
func (sc Scenario) Apply(cfg Config) (Config, []Rule, error) {
	p, err := LoadProfile(sc.Profile)
	if err != nil {
		return cfg, nil, err
	}
	for _, raw := range []json.RawMessage{p.Config, sc.Config} {
		if len(raw) == 0 {
			continue
		}
		if err := json.Unmarshal(raw, &cfg); err != nil {
			return cfg, nil, fmt.Errorf("config: %w", err)
		}
	}
	return cfg, append(append([]Rule(nil), p.Rules...), sc.Rules...), nil
}

// ruleSet counts requests by kind and finds the rules for each.
type ruleSet struct {
	mu     sync.Mutex
	rules  []Rule
	counts map[string]int
	fired  []FiredRule
}

// FiredRule is a record of one rule matching, for GET /scenario.
type FiredRule struct {
	Rule    int    `json:"rule"`
	Request string `json:"request"`
	N       int    `json:"n"`
	At      string `json:"at"`
}

func (rs *ruleSet) match(kind string) (int, []Rule) {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	if rs.counts == nil {
		rs.counts = map[string]int{}
	}
	rs.counts[kind]++
	n := rs.counts[kind]
	var out []Rule
	for i, r := range rs.rules {
		if r.When.matches(kind, n) {
			out = append(out, r)
			rs.fired = append(rs.fired, FiredRule{Rule: i + 1, Request: kind, N: n, At: time.Now().UTC().Format(time.RFC3339Nano)})
		}
	}
	return n, out
}

func (rs *ruleSet) set(rules []Rule) {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	rs.rules = append([]Rule(nil), rules...)
	rs.counts = map[string]int{}
	rs.fired = nil
}

// ScenarioStatus is what GET /scenario reports.
type ScenarioStatus struct {
	Rules  []Rule         `json:"rules"`
	Counts map[string]int `json:"counts"`
	Fired  []FiredRule    `json:"fired"`
}

func (rs *ruleSet) status() ScenarioStatus {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	counts := map[string]int{}
	for k, v := range rs.counts {
		counts[k] = v
	}
	return ScenarioStatus{Rules: append([]Rule(nil), rs.rules...), Counts: counts, Fired: append([]FiredRule(nil), rs.fired...)}
}

// SetRules replaces the scenario rules and resets the request counts.
func (s *Server) SetRules(rules []Rule) { s.rules.set(rules) }

// applyRules runs the rules for a request before the normal handler. It
// returns false if a rule answered (or closed) the request; tunnelRules are
// the rules for the tunnel this request opens, if it is one.
func (s *Server) applyRules(w http.ResponseWriter, r *http.Request) (handled bool, after []Rule, tunnel []Rule) {
	kind, ok := RequestKinds[r.URL.Path]
	if !ok {
		return false, nil, nil
	}
	n, rules := s.rules.match(kind)
	if len(rules) == 0 {
		return false, nil, nil
	}
	for _, rule := range rules {
		if rule.Delay > 0 {
			s.log.Info("scenario: delaying", "request", kind, "n", n, "seconds", rule.Delay)
			time.Sleep(time.Duration(rule.Delay * float64(time.Second)))
		}
	}
	for _, rule := range rules {
		switch {
		case rule.Do == "close":
			s.log.Info("scenario: closing without an answer", "request", kind, "n", n)
			if conn, _, err := http.NewResponseController(w).Hijack(); err == nil {
				conn.Close()
			}
			return true, nil, nil
		case rule.Respond != nil:
			s.log.Info("scenario: replacing the answer", "request", kind, "n", n, "status", rule.Respond.Status)
			status := rule.Respond.Status
			if status == 0 {
				status = http.StatusOK
			}
			if rule.Respond.Body != nil {
				writeXML(w, status, *rule.Respond.Body)
			} else {
				w.WriteHeader(status)
			}
			after = append(after, rule)
			for _, a := range rules {
				if a.Do == "drop_tunnels" || a.Do == "expire_sessions" {
					after = append(after, a)
				}
			}
			return true, after, nil
		case rule.Do == "drop_tunnel" || rule.Do == "ignore_keepalive":
			tunnel = append(tunnel, rule)
		case rule.Do == "drop_tunnels" || rule.Do == "expire_sessions":
			after = append(after, rule)
		}
	}
	return false, after, tunnel
}

func (s *Server) runAfter(rules []Rule) {
	for _, r := range rules {
		switch r.Do {
		case "drop_tunnels":
			s.log.Info("scenario: dropping tunnels", "dropped", s.DropTunnels())
		case "expire_sessions":
			s.log.Info("scenario: expiring sessions", "expired", s.ExpireSessions(""))
		}
	}
}

// LoadScenario parses a scenario and applies it to the running server.
func (s *Server) LoadScenario(data []byte) error {
	sc, err := ParseScenario(data)
	if err != nil {
		return err
	}
	cfg, rules, err := sc.Apply(s.cfg.get())
	if err != nil {
		return err
	}
	s.cfg.set(cfg)
	s.rules.set(rules)
	s.log.Info("scenario loaded", "name", sc.Name, "profile", sc.Profile, "rules", len(rules))
	return nil
}
