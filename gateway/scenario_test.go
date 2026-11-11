package gateway

import (
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestScenarioRespondByCount(t *testing.T) {
	f := newFixture(t, nil)
	err := f.srv.LoadScenario([]byte(`{
		"name": "second getconfig fails",
		"config": {"rekey": 300},
		"rules": [
			{"when": {"request": "getconfig", "nth": 2}, "respond": {"status": 200, "body": "errors getting SSL/VPN config"}},
			{"when": {"request": "hipreportcheck", "from": 2}, "respond": {"status": 500}, "_note": "ignored"}
		]
	}`))
	if err != nil {
		t.Fatal(err)
	}
	if f.srv.Config().Rekey != 300 {
		t.Errorf("config override not applied: %+v", f.srv.Config())
	}
	cookie := f.login("test", "test", "1")
	form := url.Values{"user": {"test"}, "authcookie": {cookie}}
	if code, body := f.post("/ssl-vpn/getconfig.esp", form); code != 200 || !strings.Contains(body, "<ip-address>") {
		t.Fatalf("getconfig 1 = %d %s", code, body)
	}
	if code, body := f.post("/ssl-vpn/getconfig.esp", form); code != 200 || body != "errors getting SSL/VPN config" {
		t.Fatalf("getconfig 2 = %d %q", code, body)
	}
	if code, _ := f.post("/ssl-vpn/getconfig.esp", form); code != 200 {
		t.Fatalf("getconfig 3 = %d", code)
	}
	if code, _ := f.post("/ssl-vpn/hipreportcheck.esp", form); code != 200 {
		t.Fatalf("hipreportcheck 1 = %d", code)
	}
	for i := 2; i <= 3; i++ {
		if code, _ := f.post("/ssl-vpn/hipreportcheck.esp", form); code != 500 {
			t.Fatalf("hipreportcheck %d = %d, want 500", i, code)
		}
	}
	st := f.srv.rules.status()
	if st.Counts["getconfig"] != 3 || len(st.Fired) != 3 {
		t.Errorf("status = %+v", st)
	}
}

func TestScenarioTunnelRules(t *testing.T) {
	f := newFixture(t, nil)
	err := f.srv.LoadScenario([]byte(`{
		"name": "tunnel drops, then refused",
		"rules": [
			{"when": {"request": "tunnel", "nth": 1}, "after": 0.2, "do": "drop_tunnel"},
			{"when": {"request": "tunnel", "nth": 2}, "respond": {"status": 503}},
			{"when": {"request": "tunnel", "nth": 3}, "after": 0, "do": "ignore_keepalive"}
		]
	}`))
	if err != nil {
		t.Fatal(err)
	}
	cookie := f.login("test", "test", "1")
	conn, br, head := f.openTunnel(cookie)
	if head != "START_TUNNEL" {
		t.Fatalf("tunnel 1 = %q", head)
	}
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := ReadFrame(br); err == nil {
		t.Error("tunnel 1 not dropped")
	}
	if _, _, head := f.openTunnel(cookie); !strings.HasPrefix(head, "HTTP/1.1 503") {
		t.Errorf("tunnel 2 = %q, want 503", head)
	}
	conn, br, head = f.openTunnel(cookie)
	if head != "START_TUNNEL" {
		t.Fatalf("tunnel 3 = %q", head)
	}
	time.Sleep(50 * time.Millisecond)
	conn.Write(EncodeFrame(Frame{}))
	conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	if _, err := ReadFrame(br); err == nil {
		t.Error("tunnel 3 answered a keepalive")
	}
}

func TestScenarioRejectsBadRules(t *testing.T) {
	for _, s := range []string{
		`{"rules": [{"when": {"request": "nope"}}]}`,
		`{"rules": [{"when": {"request": "login"}, "do": "explode"}]}`,
		`{"rules": [{"when": {"request": "login"}, "do": "drop_tunnel"}]}`,
		`{"transport": "esp"}`,
		`{"profile": "no-such-profile"}`,
	} {
		sc, err := ParseScenario([]byte(s))
		if err == nil {
			_, _, err = sc.Apply(DefaultConfig())
		}
		if err == nil {
			t.Errorf("accepted %s", s)
		}
	}
}

// Every committed scenario parses and applies.
func TestCommittedScenarios(t *testing.T) {
	files, _ := filepath.Glob("../scenarios/*.json")
	if len(files) == 0 {
		t.Skip("no scenarios")
	}
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		sc, err := ParseScenario(data)
		if err == nil {
			_, _, err = sc.Apply(DefaultConfig())
		}
		if err != nil {
			t.Errorf("%s: %v", file, err)
		}
		if sc.Name == "" || sc.Expect.ConnectedWithin == 0 && sc.Expect.ExitCode == nil {
			t.Errorf("%s: needs a name and an expect", file)
		}
	}
}
