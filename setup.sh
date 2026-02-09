#!/usr/bin/env bash
# setup.sh  (CLI wrapper for sepehr.sh)
#
# Usage:
#   ./setup.sh iran  <peer_public_ip> <gre_number>
#   ./setup.sh khrej <peer_public_ip> <gre_number>
#
# Fixes:
# - No hang at menu: sends multiple ENTER/0 tail to guarantee exit
# - No "unbound variable" under set -u
# - Final summary + LIVE ping over GRE using PRIVATE peer IP:
#     iran  : local 10.<n>0.<n>0.1  -> peer 10.<n>0.<n>0.2
#     khrej : local 10.<n>0.<n>0.2  -> peer 10.<n>0.<n>0.1

set -euo pipefail

# ---------------------------
# CONFIG
# ---------------------------
SEPEHR_RAW_URL="https://raw.githubusercontent.com/V2Netvpn/Sepehr-GRE-FORWARDER/main/sepehr.sh"
SEPEHR_FILE="./sepehr.sh"

PORTS="80"                 # iran side only
DEFAULT_MTU_ENABLE="n"      # y/n
DEFAULT_MTU_VALUE="1376"    # only used if DEFAULT_MTU_ENABLE=y

# Private GRE ping settings
PING_COUNT=5
PING_TIMEOUT_SEC=1

# Tail inputs to force exit from sepehr menu reliably:
# - extra ENTERs cover any "Press ENTER to continue"
# - extra 0s cover repeated menu returns
MENU_EXIT_TAIL=$'\n\n0\n0\n0\n0\n\n'

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

  systemctl stop "gre${id}.service" >/dev/null 2>&1 || true
  systemctl disable "gre${id}.service" >/dev/null 2>&1 || true

  local u
  while IFS= read -r u; do
    [[ -n "$u" ]] || continue
    systemctl stop "$u" >/dev/null 2>&1 || true
    systemctl disable "$u" >/dev/null 2>&1 || true
  done < <(systemctl list-unit-files --no-legend 2>/dev/null | awk '{print $1}' | grep -E "^fw-gre${id}-[0-9]+\.service$" || true)

  rm -f "/etc/systemd/system/gre${id}.service" >/dev/null 2>&1 || true
  rm -f /etc/systemd/system/fw-gre${id}-*.service >/dev/null 2>&1 || true

  if command -v ip >/dev/null 2>&1; then
    ip tunnel del "gre${id}" >/dev/null 2>&1 || true
  fi

  systemctl daemon-reload >/dev/null 2>&1 || true
  systemctl reset-failed  >/dev/null 2>&1 || true

  echo "[CLEAN] Done."
}

run_sepehr_with_tty() {
  local payload="$1"

  # How long we allow sepehr.sh to run before we assume it is stuck at menu
  local SEPEHR_TIMEOUT_SEC="${SEPEHR_TIMEOUT_SEC:-180}"

  # write payload to temp file (more reliable than <<< with pty)
  local tmp
  tmp="$(mktemp /tmp/sepehr_payload.XXXXXX)"
  printf "%s" "$payload" > "$tmp"

  # If timeout exists, use it to avoid Ctrl+C from user
  local TIMEOUT_BIN=""
  if command -v timeout >/dev/null 2>&1; then
    TIMEOUT_BIN="timeout -k 5s ${SEPEHR_TIMEOUT_SEC}s"
  fi

  # Prefer 'script' => pseudo-tty for interactive reads
  if command -v script >/dev/null 2>&1; then
    # Feed stdin from payload file
    # Note: some sepehr versions may loop menu forever even after 0; timeout prevents hang.
    set +e
    if [[ -n "$TIMEOUT_BIN" ]]; then
      $TIMEOUT_BIN script -q -e -c "bash $SEPEHR_FILE" /dev/null < "$tmp"
      rc=$?
    else
      script -q -e -c "bash $SEPEHR_FILE" /dev/null < "$tmp"
      rc=$?
    fi
    set -e
    rm -f "$tmp" >/dev/null 2>&1 || true
    return "$rc"
  fi

  # Fallback without script (less reliable but works)
  set +e
  if [[ -n "$TIMEOUT_BIN" ]]; then
    $TIMEOUT_BIN bash "$SEPEHR_FILE" < "$tmp"
    rc=$?
  else
    bash "$SEPEHR_FILE" < "$tmp"
    rc=$?
  fi
  set -e
  rm -f "$tmp" >/dev/null 2>&1 || true
  return "$rc"
}


gre_private_ips() {
  # input: GRE_BASE like 10.60.60.0
  # output: "local peer" based on side
  local base="$1"
  local side="$2"

  local a b c d
  IFS='.' read -r a b c d <<<"$base" || return 1

  local ip1="${a}.${b}.${c}.1"
  local ip2="${a}.${b}.${c}.2"

  if [[ "$side" == "iran" ]]; then
    echo "$ip1 $ip2"
  else
    echo "$ip2 $ip1"
  fi
}

wait_for_iface() {
  local ifname="$1"
  local tries="${2:-40}" # 40 * 0.25 = 10s
  local i
  for ((i=0; i<tries; i++)); do
    if ip link show "$ifname" >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.25
  done
  return 1
}

usage() {
  cat <<'EOF'
Usage:
  ./setup.sh iran  <peer_public_ip> <gre_number>
  ./setup.sh khrej <peer_public_ip> <gre_number>

Examples:
  ./setup.sh iran  45.89.52.101 6
  ./setup.sh khrej 54.38.224.119 6

Notes:
  - Local IPv4 detected automatically.
  - GRE base: 10.<n>0.<n>0.0 (n single digit 0..9).
  - Private ping:
      iran  => ping 10.<n>0.<n>0.2 via greN
      khrej => ping 10.<n>0.<n>0.1 via greN
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

valid_ipv4 "$PEER_IP" || die "Peer public IP invalid: $PEER_IP"
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
echo "[INFO] MTU      : ${DEFAULT_MTU_ENABLE} ${DEFAULT_MTU_VALUE}"
echo

cleanup_existing_services "$GRE_ID"
download_sepehr

# ---------------------------
# Payload builder (IMPORTANT)
# - Includes:
#   - MTU prompt answer
#   - multiple ENTERs/0 to force exit (prevents hanging at menu)
# ---------------------------
payload=""

if [[ "$SIDE" == "iran" ]]; then
  if [[ "$DEFAULT_MTU_ENABLE" == "y" ]]; then
    payload=$'1\n'"$GRE_ID"$'\n'"$LOCAL_IP"$'\n'"$PEER_IP"$'\n'"$GRE_BASE"$'\n'"$PORTS"$'\n'"$DEFAULT_MTU_ENABLE"$'\n'"$DEFAULT_MTU_VALUE""$MENU_EXIT_TAIL"
  else
    payload=$'1\n'"$GRE_ID"$'\n'"$LOCAL_IP"$'\n'"$PEER_IP"$'\n'"$GRE_BASE"$'\n'"$PORTS"$'\n'"$DEFAULT_MTU_ENABLE""$MENU_EXIT_TAIL"
  fi
else
  if [[ "$DEFAULT_MTU_ENABLE" == "y" ]]; then
    payload=$'2\n'"$GRE_ID"$'\n'"$LOCAL_IP"$'\n'"$PEER_IP"$'\n'"$GRE_BASE"$'\n'"$DEFAULT_MTU_ENABLE"$'\n'"$DEFAULT_MTU_VALUE""$MENU_EXIT_TAIL"
  else
    payload=$'2\n'"$GRE_ID"$'\n'"$LOCAL_IP"$'\n'"$PEER_IP"$'\n'"$GRE_BASE"$'\n'"$DEFAULT_MTU_ENABLE""$MENU_EXIT_TAIL"
  fi
fi

# Run installer (interactive)
set +e
run_sepehr_with_tty "$payload"
SEPEHR_RC=$?
set -e

# ---------------------------
# FINAL STATUS OUTPUT
# ---------------------------
IFACE="gre$GRE_ID"
PING_COUNT="${PING_COUNT:-5}"
PING_TIMEOUT_SEC="${PING_TIMEOUT_SEC:-1}"

echo
echo "=================================================="
echo " GRE SETUP RESULT"
echo "--------------------------------------------------"
echo " Side        : $SIDE"
echo " GRE ID      : $GRE_ID"
echo " Interface   : $IFACE"
echo " Local IP    : $LOCAL_IP"
echo " Peer IP     : $PEER_IP"
echo " GRE Base    : $GRE_BASE"
echo " MTU         : $DEFAULT_MTU_VALUE"
echo " sepehr.sh   : exit=$SEPEHR_RC"
echo "--------------------------------------------------"

# Interface state
if ip link show "$IFACE" >/dev/null 2>&1; then
  IF_STATE=$(ip link show "$IFACE" | grep -q "UP" && echo "UP" || echo "DOWN")
  echo " Interface   : $IF_STATE"
else
  echo " Interface   : NOT FOUND"
fi

# Service state
if systemctl is-active --quiet "gre$GRE_ID.service"; then
  echo " Service     : ACTIVE"
else
  echo " Service     : INACTIVE"
fi

# GRE addr (if assigned)
GRE_ADDRS=$(ip -4 addr show "$IFACE" 2>/dev/null | awk '/inet /{print $2}' | xargs || true)
if [[ -n "${GRE_ADDRS:-}" ]]; then
  echo " Tunnel IP   : $GRE_ADDRS"
else
  echo " Tunnel IP   : NOT ASSIGNED"
fi

echo "=================================================="
echo

# ---------------------------
# PRIVATE GRE PING (LIVE + SUMMARY)
# ---------------------------
echo "--------------------------------------------------"
read -r GRE_LOCAL_PRIV GRE_PEER_PRIV < <(gre_private_ips "$GRE_BASE" "$SIDE")

echo " Ping GRE    : $IFACE"
echo " Local Priv  : $GRE_LOCAL_PRIV"
echo " Peer Priv   : $GRE_PEER_PRIV (live)"

PING_LOG="/tmp/ping_peer_priv_${GRE_ID}.log"
rm -f "$PING_LOG" 2>/dev/null || true

if ! command -v ping >/dev/null 2>&1; then
  echo " Ping Result : ping command not found"
else
  if ! wait_for_iface "$IFACE" 40; then
    echo " Ping Result : FAIL (interface $IFACE not found yet)"
  else
    set +e
    ping -I "$IFACE" -c "$PING_COUNT" -W "$PING_TIMEOUT_SEC" "$GRE_PEER_PRIV" 2>&1 | tee "$PING_LOG"
    PING_RC=${PIPESTATUS[0]}
    set -e

    LOSS=$(awk -F',' '/packet loss/ {gsub(/^[ \t]+|[ \t]+$/,"",$3); print $3}' "$PING_LOG" | head -n1)
    RTT=$(awk -F'=' '/^rtt|^round-trip/ {print $2}' "$PING_LOG" | awk '{print $1}' | head -n1)

    if [[ $PING_RC -eq 0 ]]; then
      echo " Ping Result : OK (${LOSS:-"0% packet loss"})"
    else
      echo " Ping Result : FAIL (${LOSS:-"unknown loss"})"
    fi

    [[ -n "${RTT:-}" ]] && echo " RTT (ms)    : $RTT"
  fi
fi
echo "--------------------------------------------------"
echo
