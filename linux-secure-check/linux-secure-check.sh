#!/bin/bash
# ==================================================
# Linux Security Check & Hardening (with Rollback)
# Works on: Ubuntu 20.04/22.04/24.04 & AlmaLinux 8/9
# Author: Suresh Security Toolkit
# Version: 1.2 (adds --rollback, --check, --allow ports)
# ==================================================
set -euo pipefail

LOGFILE="/var/log/linux-secure-check.log"
STATE_DIR="/var/lib/linux-secure-check"
STATE_FILE="$STATE_DIR/state.env"
BACKUP_DIR="/var/backups/linux-secure-check"
TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"

mkdir -p "$STATE_DIR" "$BACKUP_DIR"
touch "$LOGFILE"

exec > >(tee -a "$LOGFILE") 2>&1
echo "[ $(date -u) ] === Linux Security Check & Hardening ==="

usage() {
  cat <<EOF
Usage: $0 [--harden] [--check] [--rollback] [--status] [--allow \"22,80,443\"] [--force]
  --harden     Apply security hardening (default action if none specified)
  --check      Run audit-only checks (no changes)
  --rollback   Restore previous configs and firewall rules
  --status     Show key security settings
  --allow      Comma-separated ports to allow (in addition to SSH)
  --force      Proceed even if password auth is currently the only way in
Examples:
  sudo $0 --harden --allow "80,443"
  sudo $0 --check
  sudo $0 --rollback
EOF
}

# ------------------------------
# OS Detect
# ------------------------------
OS=""
VER=""
if [ -f /etc/os-release ]; then
  . /etc/os-release
  OS="$ID"
  VER="$VERSION_ID"
else
  OS=$(uname -s)
  VER=$(uname -r)
fi
echo "[INFO] Detected OS: $OS $VER"

# ------------------------------
# Arg parsing
# ------------------------------
ACTION="harden"
ALLOW_PORTS=""
FORCE="no"

while [ $# -gt 0 ]; do
  case "$1" in
    --harden) ACTION="harden";;
    --check) ACTION="check";;
    --rollback) ACTION="rollback";;
    --status) ACTION="status";;
    --allow) shift; ALLOW_PORTS="${1:-}";;
    --force) FORCE="yes";;
    -h|--help) usage; exit 0;;
    *) echo "[WARN] Unknown option: $1"; usage; exit 1;;
  esac
  shift
done

# ------------------------------
# Helpers
# ------------------------------
save_state() {
  echo "$1" >> "$STATE_FILE"
}

backup_file() {
  local src="$1"
  if [ -f "$src" ]; then
    local base="$(basename "$src")"
    local dest="$BACKUP_DIR/${base}.${TIMESTAMP}.bak"
    cp -a "$src" "$dest"
    echo "[BACKUP] $src -> $dest"
    save_state "RESTORE_FILE::$src::$dest"
  fi
}

backup_dir() {
  local src="$1"
  if [ -d "$src" ]; then
    local base="$(basename "$src")"
    local dest="$BACKUP_DIR/${base}.${TIMESTAMP}.tar.gz"
    tar -czf "$dest" -C "$(dirname "$src")" "$base"
    echo "[BACKUP] $src -> $dest"
    save_state "RESTORE_DIR::$src::$dest"
  fi
}

restore_state() {
  if [ ! -f "$STATE_FILE" ]; then
    echo "[ERROR] No previous state found: $STATE_FILE"
    exit 1
  fi
  tac "$STATE_FILE" | while IFS= read -r line; do
    case "$line" in
      RESTORE_FILE::*)
        local_path="$(echo "$line" | cut -d: -f3)"
        backup_path="$(echo "$line" | cut -d: -f4)"
        if [ -f "$backup_path" ]; then
          cp -a "$backup_path" "$local_path"
          echo "[RESTORE] file $local_path <- $backup_path"
        fi
        ;;
      RESTORE_DIR::*)
        local_dir="$(echo "$line" | cut -d: -f3)"
        backup_tgz="$(echo "$line" | cut -d: -f4)"
        if [ -f "$backup_tgz" ]; then
          rm -rf "$local_dir"
          mkdir -p "$(dirname "$local_dir")"
          tar -xzf "$backup_tgz" -C "$(dirname "$local_dir")"
          echo "[RESTORE] dir  $local_dir <- $backup_tgz"
        fi
        ;;
      DISABLE_SERVICE::*)
        svc="$(echo "$line" | cut -d: -f3)"
        systemctl disable --now "$svc" || true
        echo "[RESTORE] disabled service: $svc"
        ;;
      FIREWALL_RESTORE::*)
        fw="$(echo "$line" | cut -d: -f3)"
        if [ "$fw" = "ufw" ]; then
          backup_dir "/etc/ufw" >/dev/null 2>&1 || true
        fi
        ;;
    esac
  done
  echo "[OK] Configs restored from previous backups."
}

ssh_config_has_password_only() {
  # return 0 if PasswordAuthentication yes AND no authorized_keys for current user
  local pass=$(grep -Ei '^\s*PasswordAuthentication\s+yes' /etc/ssh/sshd_config || true)
  local keys_present="no"
  for d in /root /home/*; do
    if [ -d "$d/.ssh" ] && [ -s "$d/.ssh/authorized_keys" ]; then
      keys_present="yes"
      break
    fi
  done
  if [ -n "$pass" ] && [ "$keys_present" = "no" ]; then
    return 0
  else
    return 1
  fi
}

allow_firewall_ports() {
  local ports_csv="$1"
  [ -z "$ports_csv" ] && return 0
  IFS=',' read -ra ports <<< "$ports_csv"
  for p in "${ports[@]}"; do
    p="$(echo "$p" | xargs)"
    [ -z "$p" ] && continue
    if [[ "$OS" == "ubuntu" ]]; then
      ufw allow "$p"
      echo "[UFW] allowed port $p"
    else
      firewall-cmd --permanent --add-port="${p}/tcp"
      echo "[FIREWALLD] allowed port $p/tcp"
    fi
  done
  if [[ "$OS" != "ubuntu" ]]; then firewall-cmd --reload; fi
}

# ------------------------------
# Audit / Status
# ------------------------------
audit_summary() {
  echo "----- Audit Summary -----"
  echo "[System] Host: $(hostname) | Kernel: $(uname -r) | Time: $(date -u +%FT%TZ)"
  echo "[Users] Logged in:"; who || true
  echo "[SSH]   Settings:"; grep -E '^(PasswordAuthentication|PermitRootLogin|X11Forwarding|MaxAuthTries)' /etc/ssh/sshd_config || true
  echo "[Firewall] Status:"
  if [[ "$OS" == "ubuntu" ]]; then ufw status || true; else firewall-cmd --list-all || true; fi
  echo "[Updates]"
  if [[ "$OS" == "ubuntu" ]]; then apt-get -s upgrade | grep -E 'upgraded,|Inst ' || true; else dnf check-update || true; fi
  echo "[Auditd]"; systemctl is-active auditd || true
  echo "[Pwquality]" ; [ -f /etc/security/pwquality.conf ] && cat /etc/security/pwquality.conf || echo "missing"
  echo "--------------------------"
}

# ------------------------------
# Hardening steps
# ------------------------------
do_harden() {
  echo "[TASK] Updating packages..."
  if [[ "$OS" == "ubuntu" ]]; then
    apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get -y upgrade
  elif [[ "$OS" == "almalinux" || "$OS" == "centos" ]]; then
    dnf -y update
  fi

  echo "[TASK] SSH hardening..."
  backup_file /etc/ssh/sshd_config

  if ssh_config_has_password_only && [ "$FORCE" = "no" ]; then
    echo "[ABORT] It looks like password auth is the only way in (no authorized_keys found)."
    echo "        Re-run with --force if you are on console or confident you won't lock yourself out."
    exit 2
  fi

  sed -i 's/^\s*#\?\s*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
  sed -i 's/^\s*#\?\s*PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
  sed -i 's/^\s*#\?\s*X11Forwarding.*/X11Forwarding no/' /etc/ssh/sshd_config
  if grep -qE '^\s*MaxAuthTries' /etc/ssh/sshd_config; then
    sed -i 's/^\s*MaxAuthTries.*/MaxAuthTries 3/' /etc/ssh/sshd_config
  else
    echo "MaxAuthTries 3" >> /etc/ssh/sshd_config
  fi
  systemctl restart sshd
  echo "[OK] SSH hardened."

  echo "[TASK] Firewall configuration..."
  if [[ "$OS" == "ubuntu" ]]; then
    apt-get install -y ufw
    backup_dir /etc/ufw
    ufw --force reset
    ufw default deny incoming
    ufw default allow outgoing
    ufw allow ssh
    allow_firewall_ports "$ALLOW_PORTS"
    yes | ufw enable
    save_state "FIREWALL_RESTORE::ufw"
  else
    dnf install -y firewalld
    systemctl enable --now firewalld
    backup_dir /etc/firewalld
    firewall-cmd --permanent --set-default-zone=public
    firewall-cmd --permanent --add-service=ssh
    allow_firewall_ports "$ALLOW_PORTS"
    firewall-cmd --reload
    save_state "FIREWALL_RESTORE::firewalld"
  fi
  echo "[OK] Firewall configured."

  echo "[TASK] Password policy (pwquality)..."
  if [[ "$OS" == "ubuntu" ]]; then
    apt-get install -y libpam-pwquality
  else
    dnf install -y libpwquality
  fi
  backup_file /etc/security/pwquality.conf
  cat > /etc/security/pwquality.conf <<'EOF'
minlen = 12
dcredit = -1
ucredit = -1
ocredit = -1
lcredit = -1
maxrepeat = 3
# enforce for root too
enforce_for_root
EOF
  echo "[OK] Password complexity enforced."

  echo "[TASK] Rootkit / malware scanners..."
  if [[ "$OS" == "ubuntu" ]]; then
    apt-get install -y chkrootkit rkhunter
  else
    dnf install -y epel-release
    dnf install -y chkrootkit rkhunter
  fi
  chkrootkit || true
  rkhunter --update || true
  rkhunter --propupd || true
  rkhunter --checkall --skip-keypress || true

  echo "[TASK] Log rotation & journal vacuum..."
  logrotate -f /etc/logrotate.conf || true
  journalctl --vacuum-time=14d || true

  echo "[TASK] Auditd..."
  if [[ "$OS" == "ubuntu" ]]; then
    apt-get install -y auditd
  else
    dnf install -y audit
  fi
  systemctl enable --now auditd
  save_state "DISABLE_SERVICE::rpcbind"  # example placeholder if enabled later

  echo "--------------------------------------------"
  echo "[DONE] Hardening Completed. Backups in $BACKUP_DIR"
  echo "       State file: $STATE_FILE"
  echo "--------------------------------------------"
}

# ------------------------------
# Rollback
# ------------------------------
do_rollback() {
  echo "[TASK] Rolling back using $STATE_FILE ..."
  restore_state

  echo "[TASK] Reloading services..."
  systemctl restart sshd || true
  if [[ "$OS" == "ubuntu" ]]; then
    ufw disable || true
    echo "[NOTE] UFW disabled. You may re-enable manually if desired."
  else
    systemctl restart firewalld || true
  fi
  echo "--------------------------------------------"
  echo "[DONE] Rollback Completed."
  echo "--------------------------------------------"
}

# ------------------------------
# Status
# ------------------------------
do_status() {
  audit_summary
}

# ------------------------------
# Check (audit only)
# ------------------------------
do_check() {
  audit_summary
  echo "[CHECK] rkhunter quick check (skip if not installed)"
  command -v rkhunter >/dev/null 2>&1 && rkhunter --checkall --sk || echo "rkhunter not installed"
  echo "[CHECK] chkrootkit (skip if not installed)"
  command -v chkrootkit >/dev/null 2>&1 && chkrootkit || echo "chkrootkit not installed"
}

# ------------------------------
# Main
# ------------------------------
case "$ACTION" in
  harden)  do_harden ;;
  rollback) do_rollback ;;
  status)  do_status ;;
  check)   do_check ;;
  *) usage; exit 1;;
esac
