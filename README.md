# gp-fake-gateway

A fake Palo Alto GlobalProtect portal and gateway, for testing openconnect-based clients without a real VPN.

It speaks enough of the protocol to drive openconnect's `--protocol=gp` client end to end: prelogin, portal config, gateway login with a second-factor challenge (answered with `1`, like a Duo push), getconfig, HIP check and report, logout, and a working HTTPS (GPST) tunnel. Inside the tunnel it answers ICMP and ICMPv6 echo, and echoes UDP sent to port 7. A JSON control API lets tests inspect sessions and inject faults.

ESP is not implemented; clients fall back to the HTTPS tunnel.

## Run it

```sh
go run ./cmd/fakegp -listen 127.0.0.1:8443 -control 127.0.0.1:8444
```

It prints the `--servercert` pin for its generated certificate. Then, as root:

```sh
printf 'test\n1\n' | openconnect --protocol=gp --servercert=pin-sha256:... -u test 127.0.0.1:8443
```

The default user is `test` / `test`, the challenge answer is `1`, the client gets `10.99.0.2`, and only `10.99.0.0/24` is routed into the tunnel, so `ping 10.99.0.1` goes through the fake. openconnect honors `HTTPS_PROXY`; unset it if you have one.

## Configuration

`-config file.json` merges a JSON document over the defaults (`gateway.DefaultConfig`). The same fields can be changed at runtime with `PUT /config` on the control API.

| Field | Default | Effect |
| --- | --- | --- |
| `users` | `{"test": "test"}` | user name to password |
| `second_factor` | `"challenge"` | `""` for password only |
| `second_factor_answer` | `"1"` | the answer the challenge accepts |
| `second_factor_prompt` | a Duo-style menu | the challenge's message |
| `portal_second_factor` | false | the portal's getconfig.esp challenges too (a second push for clients that log in to the portal, then the gateway) |
| `challenge_style` | `"xml"` | how the gateway sends its challenge: `"xml"` or `"javascript"` (an HTML page, as PAN-OS 11.1 does) |
| `client_ipv4`, `client_ipv6` | `10.99.0.2`, none | addresses handed out |
| `access_routes`, `exclude_routes` | `["10.99.0.0/24"]`, none | split routes (IPv4 and IPv6 mixed) |
| `dns`, `dns_suffix`, `mtu` | `10.99.0.53`, `fake.test`, 1400 | `mtu` 0 is sent as `<mtu>0</mtu>`, as a gateway with no MTU set does |
| `lifetime` | 86400 | seconds a cookie is valid after login |
| `idle_timeout` | 10800 | seconds a cookie survives with no tunnel up |
| `rekey` | 0 | if set, sent as the tunnel timeout (openconnect reconnects at rekey−60 s) |
| `new_ip_on_reconnect` | false | a different IPv4 on every getconfig |
| `hip_interval` | 3600 | portal HIP report interval, seconds |
| `hip_needed` | false | hipreportcheck asks for a report until one with that md5 arrives |
| `hip_check_fail` | false | hipreportcheck returns HTTP 500 |
| `reject_cookies` | false | every cookie is invalid |
| `drop_tunnel_after` | 0 | close each tunnel this many seconds after it starts |
| `stall_seconds` | 0 | delay every HTTP response |
| `ignore_keepalive` | false | stop answering GPST keepalives (a dead path) |

The portal never hands out an authentication override cookie (`portal-userauthcookie` is `empty`), so a client always logs in to the gateway with the password again. Response shapes (extra getconfig fields, the 22 jnlp arguments, hipreportcheck's `delay` and `quarantine`) follow a real PAN-OS 11.1 capture.

### Profiles

`-profile NAME` starts from a compiled-in profile in `gateway/profiles/`; `-config` and scenarios merge over it.

| Profile | Behaves like |
| --- | --- |
| `default` | the fake's own defaults |
| `panos-11.1` | PAN-OS 11.1.13 with Duo on portal and gateway, captured in njvack/albi#15: portal challenge, JavaScript gateway challenge, MTU 0, 72 h cookies, 12 h rekey and idle timeout, HIP report wanted on connect |

## Control API

Plain HTTP; keep it on loopback.

| Request | Does |
| --- | --- |
| `GET /config` | current config |
| `PUT /config` | merge a partial JSON config |
| `GET /sessions` | every session: cookie, IP, timers, tunnel count and state, keepalives, packets, HIP checks and the submitted HIP reports |
| `POST /sessions/expire[?user=NAME]` | expire sessions and close their tunnels |
| `POST /tunnels/drop` | close every tunnel but keep sessions valid, as a network failure would |
| `GET /scenario` | the scenario rules, request counts by kind, and every rule that fired |
| `PUT /scenario` | load a scenario: its profile and config merge over the current config, its rules replace the old ones, counts reset |

## Scenarios

`fakegp -scenario FILE` (or `PUT /scenario`) loads a scenario: a gateway profile, config overrides, and rules that fire on the nth request of a kind, such as "refuse the 2nd to 4th tunnel with 503" or "stop answering keepalives 30 s into the first tunnel". Scenarios are how a gateway bug seen in an Albi incident file becomes a regression test. [scenarios/README.md](scenarios/README.md) has the format and the steps; the files in `scenarios/` run in Albi's CI.

## Tests

`go test ./...` covers framing, the packet responder, login, config, HIP, the tunnel, cookie expiry and logout.

`e2e/run.sh OPENCONNECT FAKEGP` runs a real openconnect against the fake over a real tun device (Linux, root). It checks traffic, reconnect after a dropped tunnel, exit code 2 after the session expires, and HIP report submission. CI builds openconnect from the `macos` branch of `njvack/openconnect` (override with the `OPENCONNECT_REF` repository variable) and runs it on every push.

It also tests a failed HIP recheck. Upstream openconnect ends the session there, which the script reports as `KNOWN` without failing. With the `macos` branch's HIP-retry patch the session survives, and the script then checks that a recheck succeeds again and traffic still flows once the fault clears. Set `E2E_EXPECT_HIP_RETRY=1` to make the upstream behavior a failure.
