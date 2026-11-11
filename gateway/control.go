package gateway

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"io"
	"math/big"
	"net"
	"net/http"
	"time"
)

// ControlHandler is a plain-HTTP JSON API for tests to inspect and steer the
// gateway. Serve it on a loopback address, never next to the GP endpoints.
//
//	GET  /config            current config
//	PUT  /config            merge a partial JSON config
//	GET  /sessions          every session, with tunnel and HIP state
//	POST /sessions/expire   expire all sessions, or ?user=NAME
//	POST /tunnels/drop      close every tunnel, keeping sessions valid
func (s *Server) ControlHandler() http.Handler {
	mux := http.NewServeMux()
	writeJSON := func(w http.ResponseWriter, v any) {
		w.Header().Set("Content-Type", "application/json")
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		enc.Encode(v)
	}
	mux.HandleFunc("GET /config", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, s.cfg.get())
	})
	mux.HandleFunc("PUT /config", func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		cfg, err := s.cfg.merge(body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		s.log.Info("config changed", "body", string(body))
		writeJSON(w, cfg)
	})
	mux.HandleFunc("GET /sessions", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, s.Sessions())
	})
	mux.HandleFunc("POST /sessions/expire", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]int{"expired": s.ExpireSessions(r.URL.Query().Get("user"))})
	})
	mux.HandleFunc("POST /tunnels/drop", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]int{"dropped": s.DropTunnels()})
	})
	return mux
}

// SelfSignedCert makes a throwaway ECDSA certificate for the given host
// names and IPs, and returns it with its openconnect pin
// ("pin-sha256:<base64 SHA-256 of the public key>").
func SelfSignedCert(hosts []string) (tls.Certificate, string, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "fake GlobalProtect gateway"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(30 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	pin, err := Pin(der)
	return cert, pin, err
}

// Pin returns openconnect's --servercert pin for a DER certificate.
func Pin(der []byte) (string, error) {
	c, err := x509.ParseCertificate(der)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(c.RawSubjectPublicKeyInfo)
	return "pin-sha256:" + base64.StdEncoding.EncodeToString(sum[:]), nil
}
