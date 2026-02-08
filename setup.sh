#!/usr/bin/env bash
# setup.sh  (CLI wrapper for NEW sepehr.sh that includes MTU prompt)

set -euo pipefail

SEPEHR_RAW_URL="https://raw.githubusercontent.com/V2Netvpn/Sepehr-GRE-FORWARDER/main/sepehr.sh"
SEPEHR_FILE="./sepehr.sh"

PORTS="80"                  # iran only
DEFAULT_MTU_ENABLE="n"       # ✅ requested
DEFAULT_MTU_VALUE="1376"     # used only if DEFAULT_MTU_ENABLE=y

die() { echo "ERROR: $*" >&2; exit 1; }

valid_octet() { local o="$1"; [[ "$o" =~ ^[0-9]+$ ]] && ((o>=0 && o<=255)); }
valid_ipv4() {
  local ip="${1:-}"
  [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
  local a b c d
  IFS='.' read -r a b c d <<<"$ip"
  valid_octet "$a" && valid_octet "$b" && valid_octet "$c" && valid_octet "$d"
}

ensure_root() { [[ "${EUID:-0}" -eq 0 ]] || exec sudo -E bash "$0" "$@"; }

get_local_ipv4() {
  local ip=""
  if command -v ip >/dev/null 2>&1; then
    ip="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '/src/{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}' || true)"
  fi
  if [[ -z "$ip" ]] && command -v hostname >/dev/null 2>&1; then
    ip="$(hostname -I 2>/dev/null | awk '{print $1}' || true)"
  fi
  valid_ipv4 "$ip" || die "Cannot detect valid local IPv4."
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
  if command -v script >/dev/null 2>&1; then
    script -q -c "bash $SEPEHR_FILE" /dev/null <<<"$payload"
    return $?
  fi
  printf "%s" "$payload" | bash "$SEPEHR_FILE"
}

usage() {
  cat <<'EOF'
Usage:
  ./setup.sh iran  <peer_ip> <gre_number>
  ./setup.sh khrej <peer_ip> <gre_number>
EOF
}

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

# Normalize MTU enable
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
echo "[INFO] MTU      : ${DEFAULT_MTU_ENABLE}"
echo

cleanup_existing_services "$GRE_ID"
download_sepehr

# Build payload:
# - Always answer MTU question with y/n
# - Only send MTU value if y
if [[ "$SIDE" == "iran" ]]; then
  if [[ "$DEFAULT_MTU_ENABLE" == "y" ]]; then
    payload=$(
      printf "1\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n\n0\n" \
        "$GRE_ID" "$LOCAL_IP" "$PEER_IP" "$GRE_BASE" "$PORTS" \
        "$DEFAULT_MTU_ENABLE" "$DEFAULT_MTU_VALUE"
    )
  else
    payload=$(
      printf "1\n%s\n%s\n%s\n%s\n%s\n%s\n\n0\n" \
        "$GRE_ID" "$LOCAL_IP" "$PEER_IP" "$GRE_BASE" "$PORTS" \
        "$DEFAULT_MTU_ENABLE"
    )
  fi
else
  if [[ "$DEFAULT_MTU_ENABLE" == "y" ]]; then
    payload=$(
      printf "2\n%s\n%s\n%s\n%s\n%s\n%s\n\n0\n" \
        "$GRE_ID" "$LOCAL_IP" "$PEER_IP" "$GRE_BASE" \
        "$DEFAULT_MTU_ENABLE" "$DEFAULT_MTU_VALUE"
    )
  else
    payload=$(
      printf "2\n%s\n%s\n%s\n%s\n%s\n\n0\n" \
        "$GRE_ID" "$LOCAL_IP" "$PEER_IP" "$GRE_BASE" \
        "$DEFAULT_MTU_ENABLE"
    )
  fi
fi

run_sepehr_with_tty "$payload"
