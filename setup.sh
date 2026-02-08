#!/usr/bin/env bash
# setup.sh — CLI wrapper for sepehr.sh (NEW version) with robust PTY input
#
# Usage:
#   ./setup.sh iran  <peer_ip> <gre_number>
#   ./setup.sh khrej <peer_ip> <gre_number>
#
# - Local IPv4 auto-detect
# - GRE base: 10.<n>0.<n>0.0   (n single digit 0..9)
# - Ports fixed: 80 (iran only)
# - MTU prompt auto-answer: DEFAULT_MTU_ENABLE (n by request)
# - Cleanup old services for greN
# - Download sepehr.sh raw
# - Run via Python PTY (more reliable than `script`)

set -euo pipefail

SEPEHR_RAW_URL="https://raw.githubusercontent.com/V2Netvpn/Sepehr-GRE-FORWARDER/main/sepehr.sh"
SEPEHR_FILE="./sepehr.sh"

PORTS="80"
DEFAULT_MTU_ENABLE="n"      # ✅ requested
DEFAULT_MTU_VALUE="1376"    # used only if MTU_ENABLE=y

die(){ echo "ERROR: $*" >&2; exit 1; }

valid_octet(){ local o="$1"; [[ "$o" =~ ^[0-9]+$ ]] && ((o>=0 && o<=255)); }
valid_ipv4(){
  local ip="${1:-}"
  [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
  local a b c d; IFS='.' read -r a b c d <<<"$ip"
  valid_octet "$a" && valid_octet "$b" && valid_octet "$c" && valid_octet "$d"
}
ensure_root(){ [[ "${EUID:-0}" -eq 0 ]] || exec sudo -E bash "$0" "$@"; }

get_local_ipv4(){
  local ip=""
  if command -v ip >/dev/null 2>&1; then
    ip="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '/src/{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}' || true)"
  fi
  if [[ -z "$ip" ]] && command -v hostname >/dev/null 2>&1; then
    ip="$(hostname -I 2>/dev/null | awk '{print $1}' || true)"
  fi
  valid_ipv4 "$ip" || die "Cannot detect valid local IPv4"
  echo "$ip"
}

build_gre_base(){
  local n="${1:-}"
  [[ "$n" =~ ^[0-9]$ ]] || die "grenumber must be single digit (0..9). Got: '$n'"
  echo "10.${n}0.${n}0.0"
}

download_sepehr(){
  command -v wget >/dev/null 2>&1 || die "wget not found"
  wget -O "$SEPEHR_FILE" "${SEPEHR_RAW_URL}?$(date +%s)" >/dev/null
  chmod +x "$SEPEHR_FILE"
}

cleanup_existing_services(){
  local id="$1"
  echo "[CLEAN] GRE${id}: stop/disable/remove old units..."

  systemctl stop "gre${id}.service" >/dev/null 2>&1 || true
  systemctl disable "gre${id}.service" >/dev/null 2>&1 || true

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

usage(){
  cat <<'EOF'
Usage:
  ./setup.sh iran  <peer_ip> <gre_number>
  ./setup.sh khrej <peer_ip> <gre_number>

Example:
  ./setup.sh iran  45.89.52.101 5
  ./setup.sh khrej 51.89.227.134 5
EOF
}

[[ $# -eq 3 ]] || { usage; exit 1; }

SIDE="$1"
PEER_IP="$2"
GRE_ID="$3"

case "$SIDE" in
  iran|IRAN) SIDE="iran" ;;
  khrej|KHREJ|kharej|KHAREJ) SIDE="khrej" ;;
  *) die "Invalid side '$SIDE' (iran|khrej)" ;;
esac

valid_ipv4 "$PEER_IP" || die "Peer IP invalid: $PEER_IP"
[[ "$GRE_ID" =~ ^[0-9]$ ]] || die "grenumber must be single digit (0..9). Got: $GRE_ID"

DEFAULT_MTU_ENABLE="${DEFAULT_MTU_ENABLE,,}"
[[ "$DEFAULT_MTU_ENABLE" == "y" || "$DEFAULT_MTU_ENABLE" == "n" ]] || die "DEFAULT_MTU_ENABLE must be y or n"

ensure_root "$@"

LOCAL_IP="$(get_local_ipv4)"
GRE_BASE="$(build_gre_base "$GRE_ID")"

echo "[INFO] SIDE     : $SIDE"
echo "[INFO] LOCAL IP : $LOCAL_IP"
echo "[INFO] PEER IP  : $PEER_IP"
echo "[INFO] GRE NUM  : $GRE_ID"
echo "[INFO] GRE BASE : $GRE_BASE"
echo "[INFO] PORTS    : $PORTS (iran only)"
echo "[INFO] MTU      : $DEFAULT_MTU_ENABLE"
echo

cleanup_existing_services "$GRE_ID"
download_sepehr

# Build payload (IMPORTANT):
# - Always send: ENTER for pause_enter
# - Always send: 0 to exit menu
# - If MTU_ENABLE=y, also send MTU value
if [[ "$SIDE" == "iran" ]]; then
  if [[ "$DEFAULT_MTU_ENABLE" == "y" ]]; then
    PAYLOAD=$'1\n'"$GRE_ID"$'\n'"$LOCAL_IP"$'\n'"$PEER_IP"$'\n'"$GRE_BASE"$'\n'"$PORTS"$'\n'"$DEFAULT_MTU_ENABLE"$'\n'"$DEFAULT_MTU_VALUE"$'\n\n0\n'
  else
    PAYLOAD=$'1\n'"$GRE_ID"$'\n'"$LOCAL_IP"$'\n'"$PEER_IP"$'\n'"$GRE_BASE"$'\n'"$PORTS"$'\n'"$DEFAULT_MTU_ENABLE"$'\n\n0\n'
  fi
else
  if [[ "$DEFAULT_MTU_ENABLE" == "y" ]]; then
    PAYLOAD=$'2\n'"$GRE_ID"$'\n'"$LOCAL_IP"$'\n'"$PEER_IP"$'\n'"$GRE_BASE"$'\n'"$DEFAULT_MTU_ENABLE"$'\n'"$DEFAULT_MTU_VALUE"$'\n\n0\n'
  else
    PAYLOAD=$'2\n'"$GRE_ID"$'\n'"$LOCAL_IP"$'\n'"$PEER_IP"$'\n'"$GRE_BASE"$'\n'"$DEFAULT_MTU_ENABLE"$'\n\n0\n'
  fi
fi

# Run sepehr.sh in a real PTY and feed payload reliably
python3 - <<'PY'
import os, pty, sys, time, select, signal

sepehr = os.environ.get("SEPEHR_FILE", "./sepehr.sh")
payload = os.environ.get("PAYLOAD", "")

pid, fd = pty.fork()
if pid == 0:
  os.execvp("bash", ["bash", sepehr])

# parent
os.set_blocking(fd, False)

# write payload
os.write(fd, payload.encode())

start = time.time()
timeout = 90  # seconds
sent_extra_zero = False

buf = b""
while True:
  if time.time() - start > timeout:
    try:
      os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
      pass
    break

  r, _, _ = select.select([fd], [], [], 0.2)
  if not r:
    # if process still alive but might be waiting at menu, send extra "0\n" once
    if not sent_extra_zero and time.time() - start > 5:
      try:
        os.write(fd, b"0\n")
        sent_extra_zero = True
      except OSError:
        pass
    continue

  try:
    data = os.read(fd, 4096)
  except OSError:
    break
  if not data:
    break

  sys.stdout.buffer.write(data)
  sys.stdout.buffer.flush()
  buf += data

  # If we see main menu prompt, nudge exit (some systems consume earlier 0)
  if b"Select option:" in buf and not sent_extra_zero:
    try:
      os.write(fd, b"0\n")
      sent_extra_zero = True
    except OSError:
      pass

# ensure child exit
try:
  os.waitpid(pid, 0)
except Exception:
  pass
PY
