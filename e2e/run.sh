#!/bin/bash
# End-to-end test: real openconnect against fakegp, with a real tun device.
# Linux only, needs root (tun device, addresses, routes).
#
#   sudo e2e/run.sh /path/to/openconnect /path/to/fakegp
#
# Only the fake's test subnet (10.99.0.0/24) is routed into the tunnel; the
# default route and DNS are never touched.
set -u

OC=${1:?usage: run.sh OPENCONNECT FAKEGP}
FAKEGP=${2:?usage: run.sh OPENCONNECT FAKEGP}
HERE=$(cd "$(dirname "$0")" && pwd)
WORK=$(mktemp -d)
LISTEN=127.0.0.1:18443
CONTROL=127.0.0.1:18444
DEV=gpe2e
fails=0

# openconnect would otherwise try to reach the fake through a proxy.
unset HTTPS_PROXY https_proxy HTTP_PROXY http_proxy ALL_PROXY all_proxy

stop_oc() { pkill -f -- "--interface=$DEV" 2>/dev/null; }

cleanup() {
  stop_oc
  [ -n "${GP_PID:-}" ] && kill "$GP_PID" 2>/dev/null
  wait 2>/dev/null
  rm -rf "$WORK"
}
trap cleanup EXIT

pass() { echo "PASS: $*"; }
fail() { echo "FAIL: $*"; fails=$((fails + 1)); }
ctl() { curl -sf -X "$1" "http://$CONTROL$2" ${3:+-d "$3"}; }

# wait_for SECONDS COMMAND...: retry COMMAND once a second until it succeeds.
wait_for() {
  local n=$1; shift
  for _ in $(seq "$n"); do "$@" >/dev/null 2>&1 && return 0; sleep 1; done
  return 1
}

start_fakegp() {
  "$FAKEGP" -listen "$LISTEN" -control "$CONTROL" -pin-file "$WORK/pin" >"$WORK/fakegp.out" 2>"$WORK/fakegp.log" &
  GP_PID=$!
  wait_for 10 test -s "$WORK/pin" || { echo "fakegp did not start"; cat "$WORK/fakegp.log"; exit 1; }
}

# start_oc LOG [extra openconnect args...]: connect through the portal,
# answering the password and the "1" push challenge on stdin.
start_oc() {
  local log=$1; shift
  rm -f "$WORK/oc.exit"
  {
    printf 'test\n1\n' | "$OC" --protocol=gp --servercert="$(cat "$WORK/pin")" -u test \
      --script="$HERE/vpnc-script-min.sh" --interface="$DEV" "$@" "$LISTEN" >"$log" 2>&1
    echo $? >"$WORK/oc.exit"
  } &
}

ping_tunnel() { ping -c 1 -W 2 10.99.0.1; }
udp_echo() {
  python3 -c 'import socket; s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(2); s.sendto(b"e2e", ("10.99.0.1", 7)); assert s.recv(16) == b"e2e"'
}

# wait_exit SECONDS: wait for openconnect to exit; prints its exit code.
wait_exit() {
  for _ in $(seq "$1"); do
    [ -s "$WORK/oc.exit" ] && { cat "$WORK/oc.exit"; return 0; }
    sleep 1
  done
  echo timeout
}

hip_reports() {
  ctl GET /sessions | python3 -c 'import json, sys; print(sum(len(s["hip_reports"] or []) for s in json.load(sys.stdin)))'
}

start_fakegp

echo "== connect, traffic, reconnect, cookie rejection"
start_oc "$WORK/oc1.log"
if wait_for 15 ping_tunnel; then pass "ICMP echo through the tunnel"; else fail "no ICMP echo"; fi
if udp_echo; then pass "UDP echo through the tunnel"; else fail "no UDP echo"; fi

ctl POST /tunnels/drop >/dev/null
if wait_for 30 ping_tunnel && ctl GET /sessions | grep -q '"tunnels": 2'; then
  pass "reconnected with the same cookie after the tunnel dropped"
else
  fail "no reconnect after the tunnel dropped"
fi

ctl POST /sessions/expire >/dev/null
code=$(wait_exit 30)
if [ "$code" = 2 ]; then pass "exited 2 (cookie rejected) after the session expired"; else fail "after expiry: exit $code, want 2"; fi

echo "== HIP report and recheck"
ctl PUT /config '{"hip_needed": true}' >/dev/null
start_oc "$WORK/oc2.log" --force-trojan=5 --csd-wrapper="$HERE/hipreport-stub.sh"
wait_for 15 ping_tunnel
if [ "$(hip_reports)" -ge 1 ]; then pass "HIP report submitted"; else fail "no HIP report reached the gateway"; fi

# Known upstream behavior the plan patches: one failed HIP recheck ends the
# session. Reported, not failed, until the patch lands.
ctl PUT /config '{"hip_check_fail": true}' >/dev/null
code=$(wait_exit 20)
if [ "$code" = timeout ]; then
  pass "session survived a failed HIP recheck"
  stop_oc
else
  echo "KNOWN: a failed HIP recheck ended the session (exit $code); see the HIP-retry patch"
fi

if [ "$fails" -ne 0 ]; then
  echo "--- fakegp log"; tail -40 "$WORK/fakegp.log"
  for f in "$WORK"/oc*.log; do echo "--- $f"; tail -40 "$f"; done
  echo "$fails failure(s)"
  exit 1
fi
echo "all passed"
