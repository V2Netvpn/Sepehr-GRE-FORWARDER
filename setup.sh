#!/usr/bin/env bash
# setup.sh  (CLI wrapper for NEW sepehr.sh with MTU prompt + avoids menu spam/hang)
#
# Usage:
#   ./setup.sh iran  <peer_ip> <gre_number>
#   ./setup.sh khrej <peer_ip> <gre_number>
#
# Features:
# - Auto-detect LOCAL IPv4 from this server
# - GRE base: 10.<n>0.<n>0.0    (n = single digit 0..9)
# - Ports fixed to 80 (iran only)
# - MTU prompt auto-answered (DEFAULT_MTU_ENABLE="n" by request)
# - Cleans existing greN + fw-greN-* services before setup
# - Downloads latest sepehr.sh from repo
# - Runs sepehr.sh with pseudo-TTY (script) to avoid "Invalid option" spam
# - Sends ENTER for pause_enter and then 0 to exit menu (fixes hanging at menu)

set -euo pipefail

# ---------------------------
# CONFIG
# ---------------------------
SEPEHR_RAW_URL="https://raw.githubusercontent.com/V2Netvpn/Sepehr-GRE-FORWARDER/main/sepehr.sh"
SEPEHR_FILE="./sepehr.sh"

PORTS="80"                 # iran side only
DEFAULT_MTU_ENABLE="n"      # ✅ requested (y/n)
DEFAULT_MTU_VALUE="1376"    # only used if DEFAULT_MTU_ENABLE=y

# ---------------------------
# Helpers
# ---------------------------
die() { echo "ERROR: $*" >&2; exit 1; }

valid_octet() { local o="$1"; [[ "$o" =~ ^[0-9]+$ ]] && ((o>=0 && o<=255)); }

valid_ipv4() {
  local ip="${1:-}"
  [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
  local a b c d
  IFS='.' read -r a b c d <<<"$ip"
  valid_octet "$a" && valid_octet "$b" && valid_octet "$c" && valid_octet "$d"
}

ensure_root() {
  if [[ "${EUID:-0}" -ne 0 ]]; then
    exec sudo -E bash "$0" "$@"
  fi
}

get_local_ipv4() {
  local ip=""
  if command -v ip >/dev/null 2>&1; then
    ip="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '/src/{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}' || true)"
  fi
  if [[ -z "$ip" ]] && command -v hostname >/dev/null 2>&1; then
    ip="$(hostname -I 2>/dev/null | awk '{print $1}' || true)"
  fi
  valid_ipv4 "$ip" || die "Cannot detect valid local IPv4 (ip route/hostname -I failed)."
  echo "$ip"
}

build_gre_base() {
  local n="${1:-}"
  [[ "$n" =~ ^[0-9]$ ]] || die "grenumber must be single digit (0..9). Got: '$n'"
  echo "10.${n}0.${n}0.0"
}

download_sepehr() {
  command -v wget >/dev/null 2>&1 || die "wget not found"
  wget -O "$SEPEHR_FILE" "${SEPEHR_RAW_URL}?$(date +%s)" >/dev/null
  chmod +x "$SEPEHR_FILE"
}

cleanup_existing_services() {
  local id="$1"
  echo "[CLEAN] GRE${id}: stopping/disabling/removing old units if exist..."

  # Stop/disable GRE
  systemctl stop "gre${id}.service" >/dev/null 2>&1 || true
  systemctl disable "gre${id}.service" >/dev/null 2>&1 || true

  # Stop/disable forwarders
  local u
  while IFS= read -r u; do
    [[ -n "$u" ]] || continue
    systemctl stop "$u" >/dev/null 2>&1 || true
    systemctl disable "$u" >/dev/null 2>&1 || true
  done < <(systemctl list-unit-files --no-legend 2>/dev/null | awk '{print $1}' | grep -E "^fw-gre${id}-[0-9]+\.service$" || true)

  # Remove unit files
  rm -f "/etc/systemd/system/gre${id}.service" >/dev/null 2>&1 || true
  rm -f /etc/systemd/system/fw-gre${id}-*.service >/dev/null 2>&1 || true

  # Remove live tunnel (best-effort)
  if command -v ip >/dev/null 2>&1; then
    ip tunnel del "gre${id}" >/dev/null 2>&1 || true
  fi

  systemctl daemon-reload >/dev/null 2>&1 || true
  systemctl reset-failed  >/dev/null 2>&1 || true

  echo "[CLEAN] Done."
}

run_sepehr_with_tty() {
  local payload="$1"

  # Prefer 'script' => pseudo-tty for read -e safety
  if command -v script >/dev/null 2>&1; then
    script -q -c "bash $SEPEHR_FILE" /dev/null <<<"$payload"
    return $?
  fi

  # Fallback
  if command -v stdbuf >/dev/null 2>&1; then
    printf "%s" "$payload" | stdbuf -i0 -o0 -e0 bash "$SEPEHR_FILE"
    return $?
  fi

  printf "%s" "$payload" | bash "$SEPEHR_FILE"
}

usage() {
  cat <<'EOF'
Usage:
  ./setup.sh iran  <peer_ip> <gre_number>
  ./setup.sh khrej <peer_ip> <gre_number>

Examples:
  ./setup.sh iran  45.89.52.101 4
  ./setup.sh khrej 51.89.227.134 4

Notes:
  - Local IP is detected automatically.
  - GRE base is built as 10.<n>0.<n>0.0 (n single digit).
  - MTU auto-answered with DEFAULT_MTU_ENABLE (currently: n).
EOF
}

# ---------------------------
# Args
# ---------------------------
[[ $# -eq 3 ]] || { usage; exit 1; }

SIDE="$1"
PEER_IP="$2"
GRE_ID="$3"

case "$SIDE" in
  iran|IRAN) SIDE="iran" ;;
  khrej|KHREJ|kharej|KHAREJ) SIDE="khrej" ;;
  *) die "Invalid side '$SIDE'. Use: iran | khrej" ;;
esac

valid_ipv4 "$PEER_IP" || die "Peer IP invalid: $PEER_IP"
[[ "$GRE_ID" =~ ^[0-9]$ ]] || die "grenumber must be single digit (0..9). Got: $GRE_ID"

DEFAULT_MTU_ENABLE="${DEFAULT_MTU_ENABLE,,}"
[[ "$DEFAULT_MTU_ENABLE" == "y" || "$DEFAULT_MTU_ENABLE" == "n" ]] || die "DEFAULT_MTU_ENABLE must be y or n"

# ---------------------------
# Run
# ---------------------------
ensure_root "$@"

LOCAL_IP="$(get_local_ipv4)"
GRE_BASE="$(build_gre_base "$GRE_ID")"

echo "[INFO] SIDE     : $SIDE"
echo "[INFO] LOCAL IP : $LOCAL_IP"
echo "[INFO] PEER IP  : $PEER_IP"
echo "[INFO] GRE NUM  : $GRE_ID"
echo "[INFO] GRE BASE : $GRE_BASE"
echo "[INFO] PORTS    : $PORTS (iran only)"
echo "[INFO] MTU      : ${DEFAULT_MTU_ENABLE}${DEFAULT_MTU_ENABLE:+ }${DEFAULT_MTU_VALUE}"
echo

cleanup_existing_services "$GRE_ID"
download_sepehr

# ---------------------------
# Payload builder (IMPORTANT)
# - Must include:
#   - MTU prompt answer
#   - an ENTER for pause_enter
#   - then 0 to exit main menu
# ---------------------------
if [[ "$SIDE" == "iran" ]]; then
  if [[ "$DEFAULT_MTU_ENABLE" == "y" ]]; then
    payload=$'1\n'"$GRE_ID"$'\n'"$LOCAL_IP"$'\n'"$PEER_IP"$'\n'"$GRE_BASE"$'\n'"$PORTS"$'\n'"$DEFAULT_MTU_ENABLE"$'\n'"$DEFAULT_MTU_VALUE"$'\n\n0\n'
  else
    payload=$'1\n'"$GRE_ID"$'\n'"$LOCAL_IP"$'\n'"$PEER_IP"$'\n'"$GRE_BASE"$'\n'"$PORTS"$'\n'"$DEFAULT_MTU_ENABLE"$'\n\n0\n'
  fi
else
  if [[ "$DEFAULT_MTU_ENABLE" == "y" ]]; then
    payload=$'2\n'"$GRE_ID"$'\n'"$LOCAL_IP"$'\n'"$PEER_IP"$'\n'"$GRE_BASE"$'\n'"$DEFAULT_MTU_ENABLE"$'\n'"$DEFAULT_MTU_VALUE"$'\n\n0\n'
  else
    payload=$'2\n'"$GRE_ID"$'\n'"$LOCAL_IP"$'\n'"$PEER_IP"$'\n'"$GRE_BASE"$'\n'"$DEFAULT_MTU_ENABLE"$'\n\n0\n'
  fi
fi

run_sepehr_with_tty "$payload"

# ---------------------------
# FINAL STATUS OUTPUT
# ---------------------------
echo
echo "=================================================="
echo " GRE SETUP RESULT"
echo "--------------------------------------------------"
echo " Side        : $SIDE"
echo " GRE ID      : $GRE_ID"
echo " Interface   : gre$GRE_ID"
echo " Local IP    : $LOCAL_IP"
echo " Peer IP     : $PEER_IP"
echo " GRE Base    : $GRE_BASE"
echo " MTU         : $DEFAULT_MTU_VALUE"
echo "--------------------------------------------------"

# Check interface
if ip link show "gre$GRE_ID" >/dev/null 2>&1; then
  IF_STATE=$(ip link show "gre$GRE_ID" | grep -q "UP" && echo "UP" || echo "DOWN")
  echo " Interface   : $IF_STATE"
else
  echo " Interface   : NOT FOUND"
fi

# Check systemd service
if systemctl is-active --quiet "gre$GRE_ID.service"; then
  echo " Service     : ACTIVE"
else
  echo " Service     : INACTIVE"
fi

# Show GRE IPs if exist
GRE_IPS=$(ip addr show "gre$GRE_ID" 2>/dev/null | awk '/inet /{print $2}')
if [[ -n "$GRE_IPS" ]]; then
  echo " Tunnel IP   : $GRE_IPS"
else
  echo " Tunnel IP   : NOT ASSIGNED"
fi

echo "=================================================="
echo


# ---------------------------
# PING PEER CHECK (LIVE + SUMMARY)
# ---------------------------
echo "--------------------------------------------------"
echo " Ping Peer   : $PEER_IP (live)"

PING_LOG="/tmp/ping_peer_${GRE_ID}.log"
rm -f "$PING_LOG" 2>/dev/null || true

if command -v ping >/dev/null 2>&1; then
  # live output on screen + save to log
  set +e
  ping -c "$PING_COUNT" -W "$PING_TIMEOUT_SEC" "$PEER_IP" 2>&1 | tee "$PING_LOG"
  PING_RC=${PIPESTATUS[0]}
  set -e

  # summary
  LOSS=$(awk -F',' '/packet loss/ {gsub(/^[ \t]+|[ \t]+$/,"",$3); print $3}' "$PING_LOG" | head -n1)
  RTT=$(awk -F'=' '/^rtt|^round-trip/ {print $2}' "$PING_LOG" | awk '{print $1}' | head -n1)

  if [[ $PING_RC -eq 0 ]]; then
    echo " Ping Result : OK (${LOSS:-"0% packet loss"})"
  else
    echo " Ping Result : FAIL (${LOSS:-"unknown loss"})"
  fi

  [[ -n "$RTT" ]] && echo " RTT (ms)    : $RTT"
else
  echo " Ping Result : ping command not found"
fi

