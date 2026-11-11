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
| `client_ipv4`, `client_ipv6` | `10.99.0.2`, none | addresses handed out |
| `access_routes`, `exclude_routes` | `["10.99.0.0/24"]`, none | split routes (IPv4 and IPv6 mixed) |
| `dns`, `dns_suffix`, `mtu` | `10.99.0.53`, `fake.test`, 1400 | |
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

## Control API

Plain HTTP; keep it on loopback.

| Request | Does |
| --- | --- |
| `GET /config` | current config |
| `PUT /config` | merge a partial JSON config |
| `GET /sessions` | every session: cookie, IP, timers, tunnel count and state, keepalives, packets, HIP checks and the submitted HIP reports |
| `POST /sessions/expire[?user=NAME]` | expire sessions and close their tunnels |
| `POST /tunnels/drop` | close every tunnel but keep sessions valid, as a network failure would |

## Tests

`go test ./...` covers framing, the packet responder, login, config, HIP, the tunnel, cookie expiry and logout.

`e2e/run.sh OPENCONNECT FAKEGP` runs a real openconnect against the fake over a real tun device (Linux, root). It checks traffic, reconnect after a dropped tunnel, exit code 2 after the session expires, and HIP report submission. CI builds openconnect from the `macos` branch of `njvack/openconnect` (override with the `OPENCONNECT_REF` repository variable) and runs it on every push.

It also tests a failed HIP recheck. Upstream openconnect ends the session there, which the script reports as `KNOWN` without failing. With the `macos` branch's HIP-retry patch the session survives, and the script then checks that a recheck succeeds again and traffic still flows once the fault clears. Set `E2E_EXPECT_HIP_RETRY=1` to make the upstream behavior a failure.
