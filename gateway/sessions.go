package gateway

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"
)

// HIPReport is one report a client submitted to hipreport.esp.
type HIPReport struct {
	Received time.Time `json:"received"`
	MD5      string    `json:"md5"`
	Report   string    `json:"report"`
}

// Session is one logged-in client, identified by its authcookie.
type Session struct {
	AuthCookie string    `json:"authcookie"`
	User       string    `json:"user"`
	Portal     string    `json:"portal"`
	Domain     string    `json:"domain"`
	Computer   string    `json:"computer"`
	IPv4       string    `json:"ipv4"`
	IPv6       string    `json:"ipv6,omitempty"`
	Issued     time.Time `json:"issued"`
	LastSeen   time.Time `json:"last_seen"`
	Expired    bool      `json:"expired"`
	LoggedOut  bool      `json:"logged_out"`

	Configs    int         `json:"configs"`     // getconfig.esp calls so far
	Tunnels    int         `json:"tunnels"`     // tunnel connections made so far
	TunnelUp   bool        `json:"tunnel_up"`   // a tunnel is connected right now
	Keepalives int         `json:"keepalives"`  // GPST keepalives answered
	PacketsIn  int         `json:"packets_in"`  // data packets from the client
	PacketsOut int         `json:"packets_out"` // data packets to the client
	HIPChecks  int         `json:"hip_checks"`
	HIPReports []HIPReport `json:"hip_reports"`
}

// sessionStore keeps sessions by authcookie.
type sessionStore struct {
	mu       sync.Mutex
	sessions map[string]*Session
	now      func() time.Time
}

func newSessionStore(now func() time.Time) *sessionStore {
	return &sessionStore{sessions: map[string]*Session{}, now: now}
}

func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

func (s *sessionStore) create(sess *Session) *Session {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess.AuthCookie = randomHex(16)
	sess.Issued = s.now()
	sess.LastSeen = sess.Issued
	s.sessions[sess.AuthCookie] = sess
	return sess
}

// valid reports whether a session can still be used under cfg's timers,
// marking it expired if not. Callers hold s.mu.
func (s *sessionStore) validLocked(sess *Session, cfg Config) bool {
	if sess.Expired || sess.LoggedOut || cfg.RejectCookies {
		return false
	}
	now := s.now()
	if cfg.Lifetime > 0 && now.Sub(sess.Issued) > time.Duration(cfg.Lifetime)*time.Second {
		sess.Expired = true
		return false
	}
	if !sess.TunnelUp && cfg.IdleTimeout > 0 && now.Sub(sess.LastSeen) > time.Duration(cfg.IdleTimeout)*time.Second {
		sess.Expired = true
		return false
	}
	return true
}

// use looks up a session by cookie and user, checks it is valid, records
// activity, and runs fn on it under the lock. It returns false if there is
// no usable session.
func (s *sessionStore) use(cookie, user string, cfg Config, fn func(*Session)) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[cookie]
	if !ok || (user != "" && sess.User != user) || !s.validLocked(sess, cfg) {
		return false
	}
	sess.LastSeen = s.now()
	if fn != nil {
		fn(sess)
	}
	return true
}

// update runs fn on a session under the lock, valid or not.
func (s *sessionStore) update(cookie string, fn func(*Session)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if sess, ok := s.sessions[cookie]; ok {
		fn(sess)
	}
}

// expire marks sessions expired: all of them, or only one user's.
func (s *sessionStore) expire(user string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, sess := range s.sessions {
		if user == "" || sess.User == user {
			if !sess.Expired {
				n++
			}
			sess.Expired = true
		}
	}
	return n
}

// snapshot returns copies of every session, refreshing expiry first.
func (s *sessionStore) snapshot(cfg Config) []Session {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Session, 0, len(s.sessions))
	for _, sess := range s.sessions {
		s.validLocked(sess, cfg)
		c := *sess
		c.HIPReports = append([]HIPReport(nil), sess.HIPReports...)
		out = append(out, c)
	}
	return out
}
