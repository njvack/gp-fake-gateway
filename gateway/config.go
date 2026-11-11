// Package gateway implements a fake Palo Alto GlobalProtect portal and
// gateway, good enough to drive openconnect's GP client through login,
// configuration, HIP checks and a working HTTPS (GPST) tunnel.
package gateway

import (
	"encoding/json"
	"sync"
)

// Config controls how the fake gateway behaves. It can be changed at runtime
// through the control API; every field has a JSON name so a partial JSON
// document can be merged over the current config.
type Config struct {
	// Users maps user name to password.
	Users map[string]string `json:"users"`

	// SecondFactor is "" (none) or "challenge". With "challenge", a correct
	// password is answered with a GP challenge form, and the login only
	// completes when the client answers SecondFactorAnswer (for a Duo-style
	// push, that is "1").
	SecondFactor       string `json:"second_factor"`
	SecondFactorAnswer string `json:"second_factor_answer"`
	SecondFactorPrompt string `json:"second_factor_prompt"`

	// Tunnel configuration handed out by getconfig.esp.
	ClientIPv4    string   `json:"client_ipv4"`
	ClientIPv6    string   `json:"client_ipv6"`
	AccessRoutes  []string `json:"access_routes"`
	ExcludeRoutes []string `json:"exclude_routes"`
	DNS           []string `json:"dns"`
	DNSSuffix     []string `json:"dns_suffix"`
	MTU           int      `json:"mtu"`

	// Timers, in seconds. Lifetime is how long a cookie is valid after
	// login. IdleTimeout is how long a cookie survives with no tunnel
	// connected. Rekey, if non-zero, is sent as the tunnel timeout, which
	// makes openconnect reconnect roughly every Rekey-60 seconds.
	Lifetime    int `json:"lifetime"`
	IdleTimeout int `json:"idle_timeout"`
	Rekey       int `json:"rekey"`

	// NewIPOnReconnect hands out a different IPv4 address on every
	// getconfig, to exercise clients that must re-apply network settings.
	NewIPOnReconnect bool `json:"new_ip_on_reconnect"`

	// HIP behaviour.
	HIPInterval  int  `json:"hip_interval"`   // portal hip-report-interval, seconds
	HIPNeeded    bool `json:"hip_needed"`     // hipreportcheck says a report is needed until one arrives
	HIPCheckFail bool `json:"hip_check_fail"` // hipreportcheck.esp returns HTTP 500

	// Faults.
	RejectCookies   bool `json:"reject_cookies"`    // treat every cookie as invalid
	DropTunnelAfter int  `json:"drop_tunnel_after"` // seconds; close tunnels this long after they start
	StallSeconds    int  `json:"stall_seconds"`     // delay every HTTP response
	IgnoreKeepalive bool `json:"ignore_keepalive"`  // don't answer GPST keepalives (simulates a dead path)
}

// DefaultConfig returns the configuration used when nothing else is given.
func DefaultConfig() Config {
	return Config{
		Users:              map[string]string{"test": "test"},
		SecondFactor:       "challenge",
		SecondFactorAnswer: "1",
		SecondFactorPrompt: "Enter a passcode or select one of the following options:\n 1. Duo Push to XXX-XXX-1234\n 2. Phone call to XXX-XXX-1234",
		ClientIPv4:         "10.99.0.2",
		AccessRoutes:       []string{"10.99.0.0/24"},
		DNS:                []string{"10.99.0.53"},
		DNSSuffix:          []string{"fake.test"},
		MTU:                1400,
		Lifetime:           86400,
		IdleTimeout:        10800,
		HIPInterval:        3600,
	}
}

// configStore holds the live config behind a lock.
type configStore struct {
	mu  sync.RWMutex
	cfg Config
}

// clone returns a deep copy, so callers can't race with merges.
func (c Config) clone() Config {
	out := c
	out.Users = make(map[string]string, len(c.Users))
	for k, v := range c.Users {
		out.Users[k] = v
	}
	out.AccessRoutes = append([]string(nil), c.AccessRoutes...)
	out.ExcludeRoutes = append([]string(nil), c.ExcludeRoutes...)
	out.DNS = append([]string(nil), c.DNS...)
	out.DNSSuffix = append([]string(nil), c.DNSSuffix...)
	return out
}

func (s *configStore) get() Config {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cfg.clone()
}

// merge decodes a partial JSON document over the current config.
func (s *configStore) merge(data []byte) (Config, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := s.cfg.clone()
	if err := json.Unmarshal(data, &next); err != nil {
		return s.cfg.clone(), err
	}
	s.cfg = next
	return next.clone(), nil
}

func (s *configStore) set(c Config) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cfg = c.clone()
}
