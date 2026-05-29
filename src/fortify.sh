#!/usr/bin/env bash
set -euo pipefail

# Fortify - Declarative Linux server hardening
# Supports: Ubuntu/Debian + RHEL/Rocky/Alma
# Author: tdiprima
#
# Usage:
#   sudo bash fortify.sh --config fortify.conf              # apply
#   sudo bash fortify.sh --config fortify.conf --dry-run    # preview
#   sudo bash fortify.sh --config fortify.conf --drift      # detect drift
#   sudo bash fortify.sh --rollback                         # revert last apply

MODE="apply"
CONFIG_FILE=""
DRY_RUN="false"
APT_UPDATED="false"

STATE_DIR="/var/lib/fortify"
STATE_FILE="${STATE_DIR}/state.conf"
LAST_BACKUP_PATH=""
SSHD_BACKUP_PATH=""

# --- Output ---

COLOR_BOLD="\033[1m"
COLOR_GREEN="\033[32m"
COLOR_YELLOW="\033[33m"
COLOR_RED="\033[31m"
COLOR_CYAN="\033[36m"
COLOR_RESET="\033[0m"

ok()    { echo -e "${COLOR_GREEN}[OK]    $*${COLOR_RESET}"; }
warn()  { echo -e "${COLOR_YELLOW}[WARN]  $*${COLOR_RESET}"; }
err()   { echo -e "${COLOR_RED}[ERROR] $*${COLOR_RESET}" >&2; }
skip()  { echo -e "[SKIP]  $*"; }
dry()   { echo -e "${COLOR_YELLOW}[DRY]   $*${COLOR_RESET}"; }
drift() { echo -e "${COLOR_CYAN}[DRIFT] $*${COLOR_RESET}"; }
rmv()   { echo -e "${COLOR_RED}[DEL]   $*${COLOR_RESET}"; }

# --- Arguments ---

usage() {
  cat <<'USAGE'
Fortify - Declarative Linux server hardening

Usage:
  sudo bash fortify.sh --config <path>              Apply configuration
  sudo bash fortify.sh --config <path> --dry-run    Preview changes
  sudo bash fortify.sh --config <path> --drift      Detect configuration drift
  sudo bash fortify.sh --rollback                   Revert last apply

Options:
  --config <path>  Path to configuration file
  --dry-run        Show what would change without applying
  --drift          Compare live system state against config
  --rollback       Undo the last fortify apply (uses state file)
  -h, --help       Show this help message
USAGE
  exit 0
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --config)
        [[ $# -lt 2 ]] && { err "--config requires a path"; exit 1; }
        CONFIG_FILE="$2"
        shift 2
        ;;
      --dry-run)
        DRY_RUN="true"
        shift
        ;;
      --drift)
        MODE="drift"
        shift
        ;;
      --rollback)
        MODE="rollback"
        shift
        ;;
      -h|--help)
        usage
        ;;
      *)
        err "Unknown option: $1"
        usage
        ;;
    esac
  done
}

# --- State management ---

get_state_value() {
  local key="$1"
  if [[ -f "$STATE_FILE" ]]; then
    grep -E "^${key}=" "$STATE_FILE" 2>/dev/null | tail -1 | cut -d'=' -f2- | tr -d '"' || true
  fi
}

save_state() {
  if [[ "$DRY_RUN" == "true" ]]; then
    return 0
  fi

  mkdir -p "$STATE_DIR"
  cat >"$STATE_FILE" <<EOF
# Fortify state — do not edit manually
APPLIED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date +%Y-%m-%dT%H:%M:%SZ)"
ADMIN_USER="${ADMIN_USER}"
SSH_PORT="${SSH_PORT}"
WEB_SERVER="${WEB_SERVER}"
SSH_ALLOW_USERS="${SSH_ALLOW_USERS}"
SSH_DISABLE_PASSWORD="${SSH_DISABLE_PASSWORD}"
CONFIGURE_FIREWALL="${CONFIGURE_FIREWALL}"
ENABLE_AUTO_UPDATES="${ENABLE_AUTO_UPDATES}"
INSTALL_FAIL2BAN="${INSTALL_FAIL2BAN}"
INSTALL_LYNIS="${INSTALL_LYNIS}"
SSHD_BACKUP="${SSHD_BACKUP_PATH:-}"
EOF
  ok "State saved to ${STATE_FILE}"
}

# --- Config ---

load_config() {
  if [[ -z "$CONFIG_FILE" ]]; then
    err "Missing required --config <path>"
    echo
    usage
  fi

  if [[ ! -f "$CONFIG_FILE" ]]; then
    err "Config file not found: $CONFIG_FILE"
    exit 1
  fi

  # shellcheck disable=SC1090
  source "$CONFIG_FILE"

  # Required
  : "${ADMIN_USER:?Config missing: ADMIN_USER}"
  : "${SSH_PORT:?Config missing: SSH_PORT}"

  # Defaults for optional settings
  WEB_SERVER="${WEB_SERVER:-no}"
  SSH_ALLOW_USERS="${SSH_ALLOW_USERS:-yes}"
  SSH_DISABLE_PASSWORD="${SSH_DISABLE_PASSWORD:-yes}"
  UPDATE_PACKAGES="${UPDATE_PACKAGES:-yes}"
  CONFIGURE_FIREWALL="${CONFIGURE_FIREWALL:-yes}"
  ENABLE_AUTO_UPDATES="${ENABLE_AUTO_UPDATES:-yes}"
  INSTALL_FAIL2BAN="${INSTALL_FAIL2BAN:-yes}"
  INSTALL_LYNIS="${INSTALL_LYNIS:-yes}"
}

validate_config() {
  if ! [[ "$SSH_PORT" =~ ^[0-9]+$ ]] || [[ "$SSH_PORT" -lt 1 || "$SSH_PORT" -gt 65535 ]]; then
    err "SSH_PORT must be 1-65535, got: $SSH_PORT"
    exit 1
  fi

  if ! [[ "$ADMIN_USER" =~ ^[a-z_][a-z0-9_-]*$ ]]; then
    err "ADMIN_USER is not a valid Linux username: $ADMIN_USER"
    exit 1
  fi

  local yes_no_fields=(WEB_SERVER SSH_ALLOW_USERS SSH_DISABLE_PASSWORD UPDATE_PACKAGES CONFIGURE_FIREWALL ENABLE_AUTO_UPDATES INSTALL_FAIL2BAN INSTALL_LYNIS)
  for field in "${yes_no_fields[@]}"; do
    if [[ "${!field}" != "yes" && "${!field}" != "no" ]]; then
      err "$field must be 'yes' or 'no', got: ${!field}"
      exit 1
    fi
  done
}

print_config() {
  echo -e "${COLOR_BOLD}Configuration:${COLOR_RESET}"
  echo "  ADMIN_USER           = ${ADMIN_USER}"
  echo "  SSH_PORT             = ${SSH_PORT}"
  echo "  WEB_SERVER           = ${WEB_SERVER}"
  echo "  SSH_ALLOW_USERS      = ${SSH_ALLOW_USERS}"
  echo "  SSH_DISABLE_PASSWORD = ${SSH_DISABLE_PASSWORD}"
  echo "  UPDATE_PACKAGES      = ${UPDATE_PACKAGES}"
  echo "  CONFIGURE_FIREWALL   = ${CONFIGURE_FIREWALL}"
  echo "  ENABLE_AUTO_UPDATES  = ${ENABLE_AUTO_UPDATES}"
  echo "  INSTALL_FAIL2BAN     = ${INSTALL_FAIL2BAN}"
  echo "  INSTALL_LYNIS        = ${INSTALL_LYNIS}"
}

# --- OS detection ---

detect_os() {
  if [[ -r /etc/os-release ]]; then
    # shellcheck disable=SC1091
    source /etc/os-release
    OS_ID="${ID:-unknown}"
    OS_LIKE="${ID_LIKE:-}"
  else
    OS_ID="unknown"
    OS_LIKE=""
  fi

  if [[ "$OS_ID" == "ubuntu" || "$OS_ID" == "debian" || "$OS_LIKE" == *"debian"* ]]; then
    OS_FAMILY="debian"
  elif [[ "$OS_ID" == "rhel" || "$OS_ID" == "centos" || "$OS_ID" == "rocky" || "$OS_ID" == "almalinux" || "$OS_LIKE" == *"rhel"* || "$OS_LIKE" == *"fedora"* ]]; then
    OS_FAMILY="rhel"
  else
    OS_FAMILY="unknown"
  fi
}

detect_ssh_service() {
  if systemctl list-unit-files | grep -qE '^sshd\.service'; then
    SSH_SVC="sshd"
  else
    SSH_SVC="ssh"
  fi
}

# --- Package helpers ---

pkg_install() {
  local pkgs=("$@")
  if [[ "$OS_FAMILY" == "debian" ]]; then
    if [[ "$APT_UPDATED" != "true" ]]; then
      apt-get update -y >/dev/null 2>&1
      APT_UPDATED="true"
    fi
    DEBIAN_FRONTEND=noninteractive apt-get install -y "${pkgs[@]}"
  elif [[ "$OS_FAMILY" == "rhel" ]]; then
    dnf -y install "${pkgs[@]}" || yum -y install "${pkgs[@]}"
  else
    err "Unsupported OS family"
    exit 1
  fi
}

pkg_remove() {
  local pkgs=("$@")
  if [[ "$OS_FAMILY" == "debian" ]]; then
    DEBIAN_FRONTEND=noninteractive apt-get remove -y "${pkgs[@]}" >/dev/null 2>&1 || true
  elif [[ "$OS_FAMILY" == "rhel" ]]; then
    dnf -y remove "${pkgs[@]}" >/dev/null 2>&1 || yum -y remove "${pkgs[@]}" >/dev/null 2>&1 || true
  fi
}

service_enable_now() {
  local svc="$1"
  systemctl enable --now "$svc" >/dev/null 2>&1 || true
}

service_stop_disable() {
  local svc="$1"
  systemctl stop "$svc" >/dev/null 2>&1 || true
  systemctl disable "$svc" >/dev/null 2>&1 || true
}

backup_file() {
  local filepath="$1"
  LAST_BACKUP_PATH=""
  if [[ -f "$filepath" ]]; then
    LAST_BACKUP_PATH="${filepath}.bak.$(date +%F_%H%M%S)"
    cp -a "$filepath" "$LAST_BACKUP_PATH"
    ok "Backed up ${filepath}"
  fi
}

# --- Hardening: Packages ---

update_packages() {
  if [[ "$UPDATE_PACKAGES" != "yes" ]]; then
    skip "Package updates (UPDATE_PACKAGES=no)"
    return 0
  fi
  if [[ "$DRY_RUN" == "true" ]]; then
    dry "Would update all packages"
    return 0
  fi

  if [[ "$OS_FAMILY" == "debian" ]]; then
    apt-get update -y
    DEBIAN_FRONTEND=noninteractive apt-get upgrade -y
    apt-get autoremove -y
    APT_UPDATED="true"
  else
    dnf -y update || yum -y update
  fi
  ok "Packages updated"
}

# --- Hardening: User ---

ensure_user() {
  local username="$1"
  if id "$username" >/dev/null 2>&1; then
    ok "User '${username}' already exists"
    return 0
  fi
  if [[ "$DRY_RUN" == "true" ]]; then
    dry "Would create user '${username}'"
    return 0
  fi

  useradd -m -s /bin/bash "$username"
  ok "Created user '${username}' (set up SSH keys or password separately)"
}

grant_sudo() {
  local username="$1"
  local group
  if [[ "$OS_FAMILY" == "debian" ]]; then
    group="sudo"
  else
    group="wheel"
  fi

  if id "$username" >/dev/null 2>&1 && id -nG "$username" 2>/dev/null | grep -qw "$group"; then
    ok "User '${username}' already in ${group} group"
    return 0
  fi
  if [[ "$DRY_RUN" == "true" ]]; then
    dry "Would add '${username}' to ${group} group"
    return 0
  fi

  usermod -aG "$group" "$username"
  ok "Added '${username}' to ${group} group"
}

# --- Hardening: SSH ---

harden_sshd() {
  local cfg="/etc/ssh/sshd_config"

  if [[ "$DRY_RUN" == "true" ]]; then
    dry "Would harden ${cfg} (Port=${SSH_PORT}, PermitRootLogin=no)"
    return 0
  fi

  backup_file "$cfg"
  SSHD_BACKUP_PATH="$LAST_BACKUP_PATH"
  touch "$cfg"

  # Set or replace an sshd_config directive
  set_sshd_option() {
    local key="$1"
    local value="$2"
    if grep -qiE "^\s*${key}\s+" "$cfg"; then
      sed -i -E "s|^\s*${key}\s+.*|${key} ${value}|I" "$cfg"
    else
      echo "${key} ${value}" >> "$cfg"
    fi
  }

  set_sshd_option "PermitRootLogin" "no"
  set_sshd_option "MaxAuthTries" "3"
  set_sshd_option "LoginGraceTime" "30"
  set_sshd_option "X11Forwarding" "no"
  set_sshd_option "PermitEmptyPasswords" "no"
  set_sshd_option "PubkeyAuthentication" "yes"
  set_sshd_option "Port" "$SSH_PORT"

  if [[ "$SSH_DISABLE_PASSWORD" == "yes" ]]; then
    set_sshd_option "PasswordAuthentication" "no"
  fi

  if [[ "$SSH_ALLOW_USERS" == "yes" ]]; then
    set_sshd_option "AllowUsers" "$ADMIN_USER"
  fi

  if sshd -t >/dev/null 2>&1; then
    ok "sshd_config validated"
  else
    err "sshd_config failed validation — restoring backup"
    if [[ -n "$SSHD_BACKUP_PATH" && -f "$SSHD_BACKUP_PATH" ]]; then
      cp -a "$SSHD_BACKUP_PATH" "$cfg"
      warn "Restored from ${SSHD_BACKUP_PATH}"
    fi
    exit 1
  fi

  systemctl restart "$SSH_SVC"
  ok "SSH hardened and restarted"
}

# --- Hardening: Firewall ---

remove_fortify_firewall_rules() {
  local prev_port="$1"
  local prev_web="$2"

  if [[ "$OS_FAMILY" == "debian" ]]; then
    if [[ -n "$prev_port" ]]; then
      ufw delete allow "${prev_port}/tcp" >/dev/null 2>&1 || true
    fi
    if [[ "$prev_web" == "yes" ]]; then
      ufw delete allow 80/tcp >/dev/null 2>&1 || true
      ufw delete allow 443/tcp >/dev/null 2>&1 || true
    fi
  else
    if [[ -n "$prev_port" ]]; then
      firewall-cmd --permanent --remove-port="${prev_port}/tcp" >/dev/null 2>&1 || true
    fi
    if [[ "$prev_web" == "yes" ]]; then
      firewall-cmd --permanent --remove-service=http >/dev/null 2>&1 || true
      firewall-cmd --permanent --remove-service=https >/dev/null 2>&1 || true
    fi
    firewall-cmd --reload >/dev/null 2>&1 || true
  fi
}

cleanup_stale_firewall_rules() {
  local prev_port="$1"
  local prev_web="$2"

  # SSH port changed — remove old rule
  if [[ -n "$prev_port" && "$prev_port" != "$SSH_PORT" ]]; then
    if [[ "$OS_FAMILY" == "debian" ]]; then
      ufw delete allow "${prev_port}/tcp" >/dev/null 2>&1 || true
    else
      firewall-cmd --permanent --remove-port="${prev_port}/tcp" >/dev/null 2>&1 || true
    fi
    rmv "Removed stale SSH rule for port ${prev_port}"
  fi

  # Web server disabled — remove HTTP/HTTPS rules
  if [[ "$prev_web" == "yes" && "$WEB_SERVER" != "yes" ]]; then
    if [[ "$OS_FAMILY" == "debian" ]]; then
      ufw delete allow 80/tcp >/dev/null 2>&1 || true
      ufw delete allow 443/tcp >/dev/null 2>&1 || true
    else
      firewall-cmd --permanent --remove-service=http >/dev/null 2>&1 || true
      firewall-cmd --permanent --remove-service=https >/dev/null 2>&1 || true
    fi
    rmv "Removed stale HTTP/HTTPS rules"
  fi
}

apply_firewall_ufw() {
  pkg_install ufw

  ufw default deny incoming >/dev/null 2>&1
  ufw default allow outgoing >/dev/null 2>&1
  ufw allow "${SSH_PORT}/tcp" >/dev/null 2>&1

  if [[ "$WEB_SERVER" == "yes" ]]; then
    ufw allow 80/tcp >/dev/null 2>&1
    ufw allow 443/tcp >/dev/null 2>&1
  fi

  ufw --force enable >/dev/null 2>&1
  ok "UFW configured"
}

apply_firewall_firewalld() {
  pkg_install firewalld
  service_enable_now firewalld

  firewall-cmd --permanent --add-port="${SSH_PORT}/tcp" >/dev/null 2>&1 || true
  if [[ "$WEB_SERVER" == "yes" ]]; then
    firewall-cmd --permanent --add-service=http >/dev/null 2>&1 || true
    firewall-cmd --permanent --add-service=https >/dev/null 2>&1 || true
  fi

  firewall-cmd --reload >/dev/null 2>&1
  ok "Firewalld configured"
}

ensure_firewall() {
  local prev_configured prev_web prev_port
  prev_configured="$(get_state_value CONFIGURE_FIREWALL)"
  prev_web="$(get_state_value WEB_SERVER)"
  prev_port="$(get_state_value SSH_PORT)"

  if [[ "$CONFIGURE_FIREWALL" == "yes" ]]; then
    if [[ "$DRY_RUN" == "true" ]]; then
      dry "Would configure firewall (SSH=${SSH_PORT}, HTTP/HTTPS=${WEB_SERVER})"
      return 0
    fi
    cleanup_stale_firewall_rules "$prev_port" "$prev_web"
    if [[ "$OS_FAMILY" == "debian" ]]; then
      apply_firewall_ufw
    else
      apply_firewall_firewalld
    fi
  elif [[ "$prev_configured" == "yes" ]]; then
    if [[ "$DRY_RUN" == "true" ]]; then
      dry "Would remove fortify-managed firewall rules"
      return 0
    fi
    remove_fortify_firewall_rules "$prev_port" "$prev_web"
    rmv "Removed fortify-managed firewall rules"
  else
    skip "Firewall (CONFIGURE_FIREWALL=no)"
  fi
}

# --- Hardening: Auto updates ---

ensure_auto_updates() {
  local prev_enabled
  prev_enabled="$(get_state_value ENABLE_AUTO_UPDATES)"

  if [[ "$ENABLE_AUTO_UPDATES" == "yes" ]]; then
    if [[ "$DRY_RUN" == "true" ]]; then
      dry "Would enable automatic security updates"
      return 0
    fi
    if [[ "$OS_FAMILY" == "debian" ]]; then
      pkg_install unattended-upgrades
      dpkg-reconfigure -f noninteractive unattended-upgrades >/dev/null 2>&1 || true
      ok "Auto updates enabled (unattended-upgrades)"
    elif [[ "$OS_FAMILY" == "rhel" ]]; then
      pkg_install dnf-automatic
      service_enable_now dnf-automatic.timer
      ok "Auto updates enabled (dnf-automatic)"
    fi
  elif [[ "$prev_enabled" == "yes" ]]; then
    if [[ "$DRY_RUN" == "true" ]]; then
      dry "Would disable automatic security updates"
      return 0
    fi
    if [[ "$OS_FAMILY" == "debian" ]]; then
      service_stop_disable unattended-upgrades
      pkg_remove unattended-upgrades
      rmv "Auto updates removed (unattended-upgrades)"
    elif [[ "$OS_FAMILY" == "rhel" ]]; then
      service_stop_disable dnf-automatic.timer
      rmv "Auto updates disabled (dnf-automatic.timer)"
    fi
  else
    skip "Auto updates (ENABLE_AUTO_UPDATES=no)"
  fi
}

# --- Hardening: Fail2ban ---

ensure_fail2ban() {
  local prev_installed
  prev_installed="$(get_state_value INSTALL_FAIL2BAN)"

  if [[ "$INSTALL_FAIL2BAN" == "yes" ]]; then
    if [[ "$DRY_RUN" == "true" ]]; then
      dry "Would install and configure Fail2ban"
      return 0
    fi
    if [[ "$OS_FAMILY" == "debian" ]]; then
      pkg_install fail2ban
    else
      pkg_install epel-release || true
      pkg_install fail2ban
    fi

    mkdir -p /etc/fail2ban
    if [[ -f /etc/fail2ban/jail.conf && ! -f /etc/fail2ban/jail.local ]]; then
      cp -a /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
    fi

    cat >/etc/fail2ban/jail.d/fortify.local <<'EOF'
[sshd]
enabled = true
findtime = 10m
maxretry = 5
bantime = 1h
EOF

    service_enable_now fail2ban
    ok "Fail2ban configured and enabled"
  elif [[ "$prev_installed" == "yes" ]]; then
    if [[ "$DRY_RUN" == "true" ]]; then
      dry "Would remove Fail2ban"
      return 0
    fi
    service_stop_disable fail2ban
    rm -f /etc/fail2ban/jail.d/fortify.local
    pkg_remove fail2ban
    rmv "Fail2ban removed"
  else
    skip "Fail2ban (INSTALL_FAIL2BAN=no)"
  fi
}

# --- Hardening: Lynis ---

ensure_lynis() {
  local prev_installed
  prev_installed="$(get_state_value INSTALL_LYNIS)"

  if [[ "$INSTALL_LYNIS" == "yes" ]]; then
    if [[ "$DRY_RUN" == "true" ]]; then
      dry "Would install Lynis"
      return 0
    fi
    if [[ "$OS_FAMILY" == "debian" ]]; then
      pkg_install lynis
    else
      pkg_install epel-release || true
      pkg_install lynis
    fi
    ok "Lynis installed"
  elif [[ "$prev_installed" == "yes" ]]; then
    if [[ "$DRY_RUN" == "true" ]]; then
      dry "Would remove Lynis"
      return 0
    fi
    pkg_remove lynis
    rmv "Lynis removed"
  else
    skip "Lynis (INSTALL_LYNIS=no)"
  fi
}

# --- Drift detection ---

check_drift() {
  local has_drift="false"

  echo -e "${COLOR_BOLD}Drift detection:${COLOR_RESET}"
  echo

  # SSH port
  local live_port
  live_port="$(sshd -T 2>/dev/null | grep -i '^port ' | awk '{print $2}' || echo "unknown")"
  if [[ "$live_port" != "$SSH_PORT" ]]; then
    drift "SSH port: config=${SSH_PORT} live=${live_port}"
    has_drift="true"
  else
    ok "SSH port: ${SSH_PORT}"
  fi

  # PermitRootLogin
  local live_val
  live_val="$(sshd -T 2>/dev/null | grep -i '^permitrootlogin ' | awk '{print $2}' || echo "unknown")"
  if [[ "$live_val" != "no" ]]; then
    drift "PermitRootLogin: config=no live=${live_val}"
    has_drift="true"
  else
    ok "PermitRootLogin: no"
  fi

  # PasswordAuthentication
  if [[ "$SSH_DISABLE_PASSWORD" == "yes" ]]; then
    live_val="$(sshd -T 2>/dev/null | grep -i '^passwordauthentication ' | awk '{print $2}' || echo "unknown")"
    if [[ "$live_val" != "no" ]]; then
      drift "PasswordAuthentication: config=no live=${live_val}"
      has_drift="true"
    else
      ok "PasswordAuthentication: no"
    fi
  fi

  # User exists
  if id "$ADMIN_USER" >/dev/null 2>&1; then
    ok "User '${ADMIN_USER}' exists"
  else
    drift "User '${ADMIN_USER}' does not exist"
    has_drift="true"
  fi

  # Sudo group
  local sudo_group
  if [[ "$OS_FAMILY" == "debian" ]]; then
    sudo_group="sudo"
  else
    sudo_group="wheel"
  fi
  if id "$ADMIN_USER" >/dev/null 2>&1 && id -nG "$ADMIN_USER" 2>/dev/null | grep -qw "$sudo_group"; then
    ok "User '${ADMIN_USER}' in ${sudo_group} group"
  else
    drift "User '${ADMIN_USER}' not in ${sudo_group} group"
    has_drift="true"
  fi

  # Firewall
  if [[ "$CONFIGURE_FIREWALL" == "yes" ]]; then
    if [[ "$OS_FAMILY" == "debian" ]]; then
      if ufw status 2>/dev/null | grep -q "Status: active"; then
        ok "UFW active"
      else
        drift "UFW not active"
        has_drift="true"
      fi
    else
      if systemctl is-active firewalld >/dev/null 2>&1; then
        ok "Firewalld active"
      else
        drift "Firewalld not active"
        has_drift="true"
      fi
    fi
  fi

  # Fail2ban
  if [[ "$INSTALL_FAIL2BAN" == "yes" ]]; then
    if systemctl is-active fail2ban >/dev/null 2>&1; then
      ok "Fail2ban active"
    else
      drift "Fail2ban not active"
      has_drift="true"
    fi
  fi

  # Auto updates
  if [[ "$ENABLE_AUTO_UPDATES" == "yes" ]]; then
    if [[ "$OS_FAMILY" == "debian" ]]; then
      if dpkg -l unattended-upgrades 2>/dev/null | grep -q '^ii'; then
        ok "Auto updates installed"
      else
        drift "Auto updates (unattended-upgrades) not installed"
        has_drift="true"
      fi
    elif [[ "$OS_FAMILY" == "rhel" ]]; then
      if systemctl is-enabled dnf-automatic.timer >/dev/null 2>&1; then
        ok "Auto updates enabled"
      else
        drift "Auto updates (dnf-automatic) not enabled"
        has_drift="true"
      fi
    fi
  fi

  # Lynis
  if [[ "$INSTALL_LYNIS" == "yes" ]]; then
    if command -v lynis >/dev/null 2>&1; then
      ok "Lynis installed"
    else
      drift "Lynis not installed"
      has_drift="true"
    fi
  fi

  echo
  if [[ "$has_drift" == "true" ]]; then
    warn "Drift detected — run without --drift to converge"
    return 1
  fi
  ok "No drift — system matches config"
  return 0
}

# --- Rollback ---

do_rollback() {
  if [[ ! -f "$STATE_FILE" ]]; then
    err "No state file at ${STATE_FILE} — nothing to roll back"
    exit 1
  fi

  # Load all values before making changes
  local prev_user prev_port prev_web prev_fw prev_f2b prev_auto prev_lynis sshd_backup
  prev_user="$(get_state_value ADMIN_USER)"
  prev_port="$(get_state_value SSH_PORT)"
  prev_web="$(get_state_value WEB_SERVER)"
  prev_fw="$(get_state_value CONFIGURE_FIREWALL)"
  prev_f2b="$(get_state_value INSTALL_FAIL2BAN)"
  prev_auto="$(get_state_value ENABLE_AUTO_UPDATES)"
  prev_lynis="$(get_state_value INSTALL_LYNIS)"
  sshd_backup="$(get_state_value SSHD_BACKUP)"

  echo -e "${COLOR_BOLD}Rolling back last fortify apply:${COLOR_RESET}"
  echo

  # Restore sshd_config
  if [[ -n "$sshd_backup" && -f "$sshd_backup" ]]; then
    cp -a "$sshd_backup" /etc/ssh/sshd_config
    if sshd -t >/dev/null 2>&1; then
      systemctl restart "$SSH_SVC"
      ok "Restored sshd_config from ${sshd_backup}"
    else
      warn "Restored sshd_config but validation failed — manual review needed"
    fi
  else
    warn "No sshd_config backup found — skipping SSH rollback"
  fi

  # Remove firewall rules
  if [[ "$prev_fw" == "yes" ]]; then
    remove_fortify_firewall_rules "$prev_port" "$prev_web"
    rmv "Removed fortify firewall rules"
  fi

  # Remove fail2ban
  if [[ "$prev_f2b" == "yes" ]]; then
    service_stop_disable fail2ban
    rm -f /etc/fail2ban/jail.d/fortify.local
    pkg_remove fail2ban
    rmv "Fail2ban removed"
  fi

  # Disable auto updates
  if [[ "$prev_auto" == "yes" ]]; then
    if [[ "$OS_FAMILY" == "debian" ]]; then
      service_stop_disable unattended-upgrades
      pkg_remove unattended-upgrades
    elif [[ "$OS_FAMILY" == "rhel" ]]; then
      service_stop_disable dnf-automatic.timer
    fi
    rmv "Auto updates disabled"
  fi

  # Remove lynis
  if [[ "$prev_lynis" == "yes" ]]; then
    pkg_remove lynis
    rmv "Lynis removed"
  fi

  # Clean up state
  rm -f "$STATE_FILE"
  ok "State file removed"

  echo
  warn "Rollback complete. User '${prev_user}' was NOT removed — do this manually if needed."
  warn "Verify SSH access in a new terminal before closing this session."
}

# --- Summary ---

print_summary() {
  echo
  echo -e "${COLOR_BOLD}Fortify complete${COLOR_RESET}"
  echo
  echo "Next steps:"
  echo "  1. Test SSH in a new terminal:"
  echo "       ssh -p ${SSH_PORT} ${ADMIN_USER}@<SERVER_IP>"
  echo "  2. Verify SSH config:"
  echo "       sudo sshd -T | grep -E 'port|permitrootlogin|passwordauthentication|allowusers'"
  if [[ "$INSTALL_LYNIS" == "yes" ]]; then
    echo "  3. Run a security audit:"
    echo "       sudo lynis audit system"
  fi
}

# --- Main ---

main() {
  parse_args "$@"

  # Rollback uses state file, not config
  if [[ "$MODE" == "rollback" ]]; then
    if [[ "${EUID}" -ne 0 ]]; then
      err "Run as root: sudo bash $0 --rollback"
      exit 1
    fi
    detect_os
    if [[ "$OS_FAMILY" == "unknown" ]]; then
      err "Unsupported distro"
      exit 1
    fi
    detect_ssh_service
    do_rollback
    return 0
  fi

  # All other modes require a config file
  load_config
  validate_config

  if [[ "${EUID}" -ne 0 ]]; then
    err "Run as root: sudo bash $0 --config <path>"
    exit 1
  fi

  detect_os
  if [[ "$OS_FAMILY" == "unknown" ]]; then
    err "Unsupported distro. Fortify supports Ubuntu/Debian and RHEL/Rocky/Alma."
    exit 1
  fi
  detect_ssh_service

  ok "OS: ${OS_FAMILY} | SSH: ${SSH_SVC}"
  print_config
  echo

  # Drift detection mode
  if [[ "$MODE" == "drift" ]]; then
    local rc=0
    check_drift || rc=$?
    exit "$rc"
  fi

  # Apply mode
  if [[ "$DRY_RUN" == "true" ]]; then
    warn "Dry-run mode — no changes will be applied"
    echo
  fi

  update_packages
  ensure_user "$ADMIN_USER"
  grant_sudo "$ADMIN_USER"
  harden_sshd
  ensure_firewall
  ensure_auto_updates
  ensure_fail2ban
  ensure_lynis
  save_state

  if [[ "$DRY_RUN" != "true" ]]; then
    print_summary
  fi
}

main "$@"
