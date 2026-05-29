#!/usr/bin/env bash
set -euo pipefail

# Fortify - Harden Linux servers (non-interactive, idempotent)
# Supports: Ubuntu/Debian + RHEL/Rocky/Alma
# Author: tdiprima
#
# Usage: sudo bash fortify.sh --config fortify.conf
#        sudo bash fortify.sh --config fortify.conf --dry-run

CONFIG_FILE=""
DRY_RUN="false"
APT_UPDATED="false"

# --- Output ---

COLOR_BOLD="\033[1m"
COLOR_GREEN="\033[32m"
COLOR_YELLOW="\033[33m"
COLOR_RED="\033[31m"
COLOR_RESET="\033[0m"

ok()   { echo -e "${COLOR_GREEN}[OK]    $*${COLOR_RESET}"; }
warn() { echo -e "${COLOR_YELLOW}[WARN]  $*${COLOR_RESET}"; }
err()  { echo -e "${COLOR_RED}[ERROR] $*${COLOR_RESET}" >&2; }
skip() { echo -e "[SKIP]  $*"; }
dry()  { echo -e "${COLOR_YELLOW}[DRY]   $*${COLOR_RESET}"; }

# --- Arguments ---

usage() {
  cat <<'USAGE'
Fortify - Non-interactive Linux server hardening

Usage: sudo bash fortify.sh --config <path> [--dry-run]

Options:
  --config <path>  Path to configuration file (required)
  --dry-run        Show what would change without applying
  -h, --help       Show this help message

Example:
  sudo bash fortify.sh --config fortify.conf
  sudo bash fortify.sh --config fortify.conf --dry-run
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
  echo -e "${COLOR_BOLD}Fortify configuration:${COLOR_RESET}"
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

# --- Helpers ---

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
    err "Unsupported OS family for package install"
    exit 1
  fi
}

service_enable_now() {
  local svc="$1"
  systemctl enable --now "$svc" >/dev/null 2>&1 || true
}

backup_file() {
  local filepath="$1"
  if [[ -f "$filepath" ]]; then
    cp -a "$filepath" "${filepath}.bak.$(date +%F_%H%M%S)"
    ok "Backed up ${filepath}"
  fi
}

# --- Hardening steps ---

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

harden_sshd() {
  local cfg="/etc/ssh/sshd_config"

  if [[ "$DRY_RUN" == "true" ]]; then
    dry "Would harden ${cfg} (Port=${SSH_PORT}, PermitRootLogin=no, PasswordAuth=${SSH_DISABLE_PASSWORD})"
    return 0
  fi

  backup_file "$cfg"
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
    local lastbak
    lastbak="$(ls -1t /etc/ssh/sshd_config.bak.* 2>/dev/null | head -n1 || true)"
    if [[ -n "$lastbak" ]]; then
      cp -a "$lastbak" "$cfg"
      warn "Restored from ${lastbak}"
    fi
    exit 1
  fi

  systemctl restart "$SSH_SVC"
  ok "SSH hardened and restarted"
}

configure_firewall() {
  if [[ "$CONFIGURE_FIREWALL" != "yes" ]]; then
    skip "Firewall (CONFIGURE_FIREWALL=no)"
    return 0
  fi
  if [[ "$DRY_RUN" == "true" ]]; then
    dry "Would configure firewall (SSH=${SSH_PORT}, HTTP/HTTPS=${WEB_SERVER})"
    return 0
  fi

  if [[ "$OS_FAMILY" == "debian" ]]; then
    configure_firewall_ufw
  else
    configure_firewall_firewalld
  fi
}

configure_firewall_ufw() {
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
  ufw status verbose || true
}

configure_firewall_firewalld() {
  pkg_install firewalld
  service_enable_now firewalld

  firewall-cmd --permanent --add-port="${SSH_PORT}/tcp" >/dev/null 2>&1 || true
  if [[ "$WEB_SERVER" == "yes" ]]; then
    firewall-cmd --permanent --add-service=http >/dev/null 2>&1 || true
    firewall-cmd --permanent --add-service=https >/dev/null 2>&1 || true
  fi

  firewall-cmd --reload >/dev/null 2>&1
  ok "Firewalld configured"
  firewall-cmd --list-all || true
}

enable_auto_updates() {
  if [[ "$ENABLE_AUTO_UPDATES" != "yes" ]]; then
    skip "Auto updates (ENABLE_AUTO_UPDATES=no)"
    return 0
  fi
  if [[ "$DRY_RUN" == "true" ]]; then
    dry "Would enable automatic security updates"
    return 0
  fi

  if [[ "$OS_FAMILY" == "debian" ]]; then
    pkg_install unattended-upgrades
    dpkg-reconfigure -f noninteractive unattended-upgrades >/dev/null 2>&1 || true
    ok "Auto security updates enabled (unattended-upgrades)"
  elif [[ "$OS_FAMILY" == "rhel" ]]; then
    pkg_install dnf-automatic
    service_enable_now dnf-automatic.timer
    ok "Auto security updates enabled (dnf-automatic)"
  fi
}

install_fail2ban() {
  if [[ "$INSTALL_FAIL2BAN" != "yes" ]]; then
    skip "Fail2ban (INSTALL_FAIL2BAN=no)"
    return 0
  fi
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
}

install_lynis() {
  if [[ "$INSTALL_LYNIS" != "yes" ]]; then
    skip "Lynis (INSTALL_LYNIS=no)"
    return 0
  fi
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
}

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

  ok "OS family: ${OS_FAMILY} | SSH service: ${SSH_SVC}"
  print_config
  echo

  if [[ "$DRY_RUN" == "true" ]]; then
    warn "Dry-run mode — no changes will be applied"
    echo
  fi

  update_packages
  ensure_user "$ADMIN_USER"
  grant_sudo "$ADMIN_USER"
  harden_sshd
  configure_firewall
  enable_auto_updates
  install_fail2ban
  install_lynis

  if [[ "$DRY_RUN" != "true" ]]; then
    print_summary
  fi
}

main "$@"
