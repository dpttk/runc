#!/usr/bin/env bash
# OCI poststop hook: tear down what setup-net.sh created.
set -u

STATE_JSON="$(cat)"
CID="$(printf '%s' "$STATE_JSON" | jq -r '.id')"
STATE_FILE="/run/runc-hooks/${CID}.env"

[ -f "$STATE_FILE" ] || exit 0
# shellcheck disable=SC1090
. "$STATE_FILE"

# NAT
iptables -t nat -D OUTPUT -p tcp --dport "$HOST_PORT" -m addrtype --dst-type LOCAL \
    -j DNAT --to-destination "${CONT_IP}:${CONT_PORT}" 2>/dev/null || true
iptables -t nat -D PREROUTING -i "$WAN_IF" -p tcp --dport "$HOST_PORT" \
    -j DNAT --to-destination "${CONT_IP}:${CONT_PORT}" 2>/dev/null || true
iptables -t nat -D POSTROUTING -p tcp -d "${CONT_IP}" --dport "$CONT_PORT" \
    -j SNAT --to-source "$HOST_IP" 2>/dev/null || true
iptables -t nat -D POSTROUTING -s "${CONT_IP}/32" -o "$WAN_IF" -j MASQUERADE 2>/dev/null || true

# FORWARD
iptables -D FORWARD -i "$WAN_IF" -o "$HOST_IF" -j ACCEPT 2>/dev/null || true
iptables -D FORWARD -i "$HOST_IF" -o "$WAN_IF" -j ACCEPT 2>/dev/null || true
iptables -D FORWARD -i "$HOST_IF" -j ACCEPT 2>/dev/null || true
iptables -D FORWARD -o "$HOST_IF" -j ACCEPT 2>/dev/null || true

ip link del "$HOST_IF" 2>/dev/null || true

rm -f "$STATE_FILE"
echo "[teardown-net:${CID:0:8}] done" >&2
