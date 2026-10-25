#!/usr/bin/env bash
# Invoked elevated (sudo/pkexec). Apply/remove IPv4 routes for full-tunnel through Xray TUN.
# Args are positional only — see VpnLinuxFullTunnelRoutes in Dart.
set -euo pipefail

_ip() {
  if command -v ip >/dev/null 2>&1; then
    command -v ip
  elif [[ -x /usr/sbin/ip ]]; then
    echo /usr/sbin/ip
  else
    echo /sbin/ip
  fi
}

IP="$(_ip)"

# Other TUN clients install `ip rule`s that run before `main` and may swallow the VPN server's own
# packets. Pin the server to `main` just above the lowest non-local rule; no fixed priority.
_server_rule_pref() {
  local lowest
  lowest="$("$IP" -4 rule show | awk -F: '$1+0>0{print $1+0; exit}')"
  if [[ -z "$lowest" || "$lowest" -le 1 ]]; then
    echo 1
  else
    echo $((lowest - 1))
  fi
}

case "${1:-}" in
apply)
  gw="${2:?}" dev="${3:?}" tun="${4:?}"
  shift 4
  dns_servers=()
  dns_domains=()
  routes=()
  manage_dns=0
  for addr in "$@"; do
    if [[ "$addr" == route=* ]]; then
      routes+=("${addr#route=}")
      continue
    fi
    if [[ "$addr" == dns-domain=* ]]; then
      dns_domains+=("${addr#dns-domain=}")
      continue
    fi
    if [[ "$addr" == manage-dns ]]; then
      manage_dns=1
      continue
    fi
    if [[ "$addr" == dns=* ]]; then
      dns_servers+=("${addr#dns=}")
      continue
    fi
    "$IP" -4 route replace "$addr/32" via "$gw" dev "$dev"
    if ! "$IP" -4 rule show | grep -q "to $addr lookup main"; then
      "$IP" -4 rule add to "$addr/32" lookup main pref "$(_server_rule_pref)" 2>/dev/null || true
    fi
  done
  if [[ ${#routes[@]} -gt 0 ]]; then
    # Split tunnel: only the listed networks go through the VPN.
    for net in "${routes[@]}"; do
      "$IP" -4 route replace "$net" dev "$tun"
    done
  else
    "$IP" -4 route replace 0.0.0.0/1 dev "$tun"
    "$IP" -4 route replace 128.0.0.0/1 dev "$tun"
  fi
  if [[ "$manage_dns" == 1 ]] && command -v resolvectl >/dev/null 2>&1; then
    if [[ ${#dns_domains[@]} -gt 0 ]]; then
      # Only the listed domains use the VPN DNS; no public fallbacks (they would answer for those names too).
      resolvectl dns "$tun" "${dns_servers[@]}" 2>/dev/null || true
      resolvectl domain "$tun" "${dns_domains[@]}" 2>/dev/null || true
      resolvectl default-route "$tun" false 2>/dev/null || true
    else
      # Prefer DNS pushed by the VPN server; public resolvers as fallback
      resolvectl dns "$tun" "${dns_servers[@]}" 1.1.1.1 8.8.8.8 2>/dev/null || true
      resolvectl domain "$tun" "~." 2>/dev/null || true
      resolvectl default-route "$tun" true 2>/dev/null || true
    fi
  fi
  ;;
undo)
  tun="${2:?}" gw="${3:?}" dev="${4:?}"
  shift 4
  if command -v resolvectl >/dev/null 2>&1; then
    resolvectl revert "$tun" 2>/dev/null || true
  fi
  "$IP" -4 route del 0.0.0.0/1 dev "$tun" 2>/dev/null || true
  "$IP" -4 route del 128.0.0.0/1 dev "$tun" 2>/dev/null || true
  for addr in "$@"; do
    if [[ "$addr" == route=* ]]; then
      "$IP" -4 route del "${addr#route=}" dev "$tun" 2>/dev/null || true
      continue
    fi
    "$IP" -4 route del "$addr/32" via "$gw" dev "$dev" 2>/dev/null || true
    while "$IP" -4 rule del to "$addr/32" lookup main 2>/dev/null; do :; done
  done
  ;;
*)
  exit 1
  ;;
esac
