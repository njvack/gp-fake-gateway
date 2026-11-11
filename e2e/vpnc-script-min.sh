#!/bin/sh
# Minimal vpnc-script for e2e tests on Linux: sets the tunnel address and the
# split routes openconnect passes, and nothing else (no DNS, no default route).
set -e
case "$reason" in
  connect)
    ip link set dev "$TUNDEV" up mtu "${INTERNAL_IP4_MTU:-1400}"
    ip addr add "$INTERNAL_IP4_ADDRESS/32" dev "$TUNDEV"
    i=0
    while [ "$i" -lt "${CISCO_SPLIT_INC:-0}" ]; do
      eval net="\$CISCO_SPLIT_INC_${i}_ADDR" len="\$CISCO_SPLIT_INC_${i}_MASKLEN"
      ip route replace "$net/$len" dev "$TUNDEV"
      i=$((i + 1))
    done
    ;;
  reconnect)
    # The tun device survives a reconnect; re-apply in case the address changed.
    ip addr flush dev "$TUNDEV" 2>/dev/null || true
    ip addr add "$INTERNAL_IP4_ADDRESS/32" dev "$TUNDEV"
    i=0
    while [ "$i" -lt "${CISCO_SPLIT_INC:-0}" ]; do
      eval net="\$CISCO_SPLIT_INC_${i}_ADDR" len="\$CISCO_SPLIT_INC_${i}_MASKLEN"
      ip route replace "$net/$len" dev "$TUNDEV"
      i=$((i + 1))
    done
    ;;
esac
exit 0
