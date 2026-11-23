#!/bin/sh
# Forward DMZ <-> internal and masquerade towards the internal network, so the targets
# answer the router (their only neighbour) and need no route of their own.
set -eu
INTERNAL="${LAB_INTERNAL:-10.66.2.0/24}"
OUT="$(ip -o -4 route show "$INTERNAL" | awk '{print $3}')"
[ -n "$OUT" ] || { echo "router: no interface on $INTERNAL" >&2; exit 1; }
iptables -t nat -A POSTROUTING -o "$OUT" -j MASQUERADE
echo "router: forwarding to $INTERNAL via $OUT (ip_forward=$(cat /proc/sys/net/ipv4/ip_forward))"
exec sleep infinity
