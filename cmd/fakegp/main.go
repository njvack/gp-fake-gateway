// Command fakegp runs a fake GlobalProtect portal and gateway for testing
// openconnect-based clients.
//
//	fakegp -listen 127.0.0.1:8443 -control 127.0.0.1:8444
//
// It prints the --servercert pin to use with openconnect, and serves a JSON
// control API (see gateway.ControlHandler) for steering it from tests.
package main

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"

	"github.com/njvack/gp-fake-gateway/gateway"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:8443", "address for the GP portal/gateway (TLS)")
	control := flag.String("control", "127.0.0.1:8444", "address for the control API (plain HTTP; keep it on loopback)")
	certFile := flag.String("cert", "", "TLS certificate (PEM); a self-signed one is generated if empty")
	keyFile := flag.String("key", "", "TLS key (PEM)")
	hosts := flag.String("hosts", "localhost,127.0.0.1,::1", "comma-separated names and IPs for the generated certificate")
	configFile := flag.String("config", "", "JSON config file, merged over the defaults")
	pinFile := flag.String("pin-file", "", "write the openconnect --servercert pin here")
	scenarioFile := flag.String("scenario", "", "scenario file (see scenarios/): a profile, config and fault rules")
	verbose := flag.Bool("v", false, "debug logging")
	flag.Parse()

	level := slog.LevelInfo
	if *verbose {
		level = slog.LevelDebug
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

	cfg := gateway.DefaultConfig()
	if *configFile != "" {
		data, err := os.ReadFile(*configFile)
		if err != nil {
			fatal(log, "read config", err)
		}
		if err := json.Unmarshal(data, &cfg); err != nil {
			fatal(log, "parse config", err)
		}
	}

	var cert tls.Certificate
	var pin string
	var err error
	if *certFile != "" {
		cert, err = tls.LoadX509KeyPair(*certFile, *keyFile)
		if err == nil {
			pin, err = gateway.Pin(cert.Certificate[0])
		}
	} else {
		cert, pin, err = gateway.SelfSignedCert(strings.Split(*hosts, ","))
	}
	if err != nil {
		fatal(log, "certificate", err)
	}
	if *pinFile != "" {
		if err := os.WriteFile(*pinFile, []byte(pin+"\n"), 0o644); err != nil {
			fatal(log, "write pin", err)
		}
	}

	srv := gateway.New(cfg, log)
	if *scenarioFile != "" {
		data, err := os.ReadFile(*scenarioFile)
		if err == nil {
			err = srv.LoadScenario(data)
		}
		if err != nil {
			fatal(log, "scenario", err)
		}
	}

	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		fatal(log, "listen", err)
	}
	if *control != "" {
		cln, err := net.Listen("tcp", *control)
		if err != nil {
			fatal(log, "listen control", err)
		}
		go http.Serve(cln, srv.ControlHandler())
		log.Info("control API", "addr", cln.Addr().String())
	}
	fmt.Printf("fakegp listening on %s\nopenconnect --protocol=gp --servercert=%s %s\n", ln.Addr(), pin, ln.Addr())
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	if err := srv.Serve(ln, tlsConfig); err != nil {
		fatal(log, "serve", err)
	}
}

func fatal(log *slog.Logger, what string, err error) {
	log.Error(what, "err", err)
	os.Exit(1)
}
