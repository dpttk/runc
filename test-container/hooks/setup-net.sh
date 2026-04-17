#!/usr/bin/env bash
# OCI prestart hook: set up veth pair + NAT + DNAT so a runc container
# with its own network namespace is reachable from the host on a given port.
#
# Reads OCI state JSON on stdin to learn {id, pid}.
set -euo pipefail

STATE_JSON="$(cat)"
CID="$(printf '%s' "$STATE_JSON" | jq -r '.id')"
PID="$(printf '%s' "$STATE_JSON" | jq -r '.pid')"

# Short, stable suffix per container to avoid iface name collisions (IFNAMSIZ=15).
SUFFIX="$(printf '%s' "$CID" | sha1sum | cut -c1-6)"
HOST_IF="rh${SUFFIX}"
CONT_IF="rc${SUFFIX}"

# /30 subnet per container keeps things isolated.
HOST_IP="10.100.0.1"
CONT_IP="10.100.0.2"
PREFIX="30"

HOST_PORT="${RUNC_HOOK_HOST_PORT:-3000}"
CONT_PORT="${RUNC_HOOK_CONT_PORT:-3000}"

# Host-side WAN interface. Auto-detected from the default route unless the
# caller overrides via RUNC_HOOK_WAN_IF (useful on hosts with multiple NICs).
WAN_IF="${RUNC_HOOK_WAN_IF:-$(ip -4 route show default | awk '{print $5; exit}')}"
if [ -z "$WAN_IF" ]; then
    echo "[setup-net] cannot determine WAN interface; set RUNC_HOOK_WAN_IF" >&2
    exit 1
fi

STATE_DIR="/run/runc-hooks"
mkdir -p "$STATE_DIR"
STATE_FILE="${STATE_DIR}/${CID}.env"

log() { echo "[setup-net:${CID:0:8}] $*" >&2; }

cleanup_on_error() {
    log "error during setup, rolling back"
    ip link del "$HOST_IF" 2>/dev/null || true
    rm -f "$STATE_FILE"
}
trap cleanup_on_error ERR

ip link add "$HOST_IF" type veth peer name "$CONT_IF"
ip link set "$CONT_IF" netns "$PID"

ip addr add "${HOST_IP}/${PREFIX}" dev "$HOST_IF"
ip link set "$HOST_IF" up

nsenter -t "$PID" -n ip link set lo up
nsenter -t "$PID" -n ip link set "$CONT_IF" name eth0
nsenter -t "$PID" -n ip addr add "${CONT_IP}/${PREFIX}" dev eth0
nsenter -t "$PID" -n ip link set eth0 up
nsenter -t "$PID" -n ip route add default via "$HOST_IP"

sysctl -q -w net.ipv4.ip_forward=1

# Outbound: only SNAT traffic that actually leaves via WAN, not docker/other bridges.
iptables -t nat -A POSTROUTING -s "${CONT_IP}/32" -o "$WAN_IF" -j MASQUERADE

# FORWARD policy on this host is DROP (Docker sets it). Insert our allow rules
# at the top so they win over DOCKER-USER/DOCKER-ISOLATION chains.
iptables -I FORWARD 1 -i "$WAN_IF" -o "$HOST_IF" -j ACCEPT
iptables -I FORWARD 1 -i "$HOST_IF" -o "$WAN_IF" -j ACCEPT
iptables -I FORWARD 1 -i "$HOST_IF" -j ACCEPT
iptables -I FORWARD 1 -o "$HOST_IF" -j ACCEPT

# Inbound from WAN: DNAT on the public-facing iface only.
iptables -t nat -A PREROUTING -i "$WAN_IF" -p tcp --dport "$HOST_PORT" \
    -j DNAT --to-destination "${CONT_IP}:${CONT_PORT}"

# Inbound from the host itself (curl to localhost, to the host IP, etc.).
# PREROUTING is skipped for locally-generated traffic, so we DNAT in OUTPUT
# for any destination that resolves to a LOCAL address on this host.
iptables -t nat -A OUTPUT -p tcp --dport "$HOST_PORT" -m addrtype --dst-type LOCAL \
    -j DNAT --to-destination "${CONT_IP}:${CONT_PORT}"
# SNAT the return path so the container sees us as 10.100.0.1 rather than
# 127.0.0.1 / the WAN IP — otherwise the reply is routed to its own loopback
# (for 127.0.0.1) or goes out of the netns on default route (for the WAN IP).
iptables -t nat -A POSTROUTING -p tcp -d "${CONT_IP}" --dport "$CONT_PORT" \
    -j SNAT --to-source "$HOST_IP"
sysctl -q -w net.ipv4.conf.all.route_localnet=1
sysctl -q -w net.ipv4.conf.lo.route_localnet=1

cat >"$STATE_FILE" <<EOF
HOST_IF=${HOST_IF}
WAN_IF=${WAN_IF}
HOST_IP=${HOST_IP}
CONT_IP=${CONT_IP}
HOST_PORT=${HOST_PORT}
CONT_PORT=${CONT_PORT}
EOF

trap - ERR
log "up: ${WAN_IF}:${HOST_PORT} -> ${CONT_IP}:${CONT_PORT} (veth ${HOST_IF})"
