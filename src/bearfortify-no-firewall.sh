#!/usr/bin/env bash

# -----------------------------------------------------------------------------
# BearFortify (No Firewall Edition)
#
# What this does:
#   - Updates packages (optional)
#   - Ensures an admin user exists + has sudo
#   - Hardens SSH:
#       • Disables root login
#       • Limits login attempts
#       • Optional custom SSH port
#       • Optional AllowUsers restriction
#       • Optional disable password auth (keys only)
#   - Validates SSH config before restart (prevents lockout)
#   - Optional auto security updates
#   - Optional Fail2ban + Lynis install
#
# Supports: Ubuntu/Debian + RHEL/Rocky/Alma
# Does NOT configure firewall.
#
# Run as root: sudo bash bearfortify-no-firewall.sh
# -----------------------------------------------------------------------------

set -euo pipefail

# BearFortify - Harden Linux servers safely (interactive)
# Supports: Ubuntu/Debian + RHEL/Rocky/Alma
# Author: Bear energy 🐻

COLOR_BOLD="\033[1m"
COLOR_GREEN="\033[32m"
COLOR_YELLOW="\033[33m"
COLOR_RED="\033[31m"
COLOR_RESET="\033[0m"

ok()   { echo -e "${COLOR_GREEN}✅ $*${COLOR_RESET}"; }
warn() { echo -e "${COLOR_YELLOW}⚠️  $*${COLOR_RESET}"; }
err()  { echo -e "${COLOR_RED}❌ $*${COLOR_RESET}"; }

title() {
  echo
  echo -e "${COLOR_BOLD}🐻 BearFortify — Safe Linux Server Hardening${COLOR_RESET}"
  echo "------------------------------------------------"
}

require_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    err "Run as root: sudo bash $0"
    exit 1
  fi
}

ask_yes_no() {
  local prompt="$1"
  local default="${2:-y}"
  local ans=""
  while true; do
    if [[ "$default" == "y" ]]; then
      read -r -p "$prompt [Y/n]: " ans
      ans="${ans:-y}"
    else
      read -r -p "$prompt [y/N]: " ans
      ans="${ans:-n}"
    fi
    case "$ans" in
      y|Y|yes|YES) return 0 ;;
      n|N|no|NO) return 1 ;;
      *) echo "Please answer y/n." ;;
    esac
  done
}

ask_input() {
  local prompt="$1"
  local default="${2:-}"
  local out=""
  if [[ -n "$default" ]]; then
    read -r -p "$prompt [$default]: " out
    out="${out:-$default}"
  else
    read -r -p "$prompt: " out
  fi
  echo "$out"
}

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

pkg_install() {
  local pkgs=("$@")
  if [[ "$OS_FAMILY" == "debian" ]]; then
    apt-get update -y
    DEBIAN_FRONTEND=noninteractive apt-get install -y "${pkgs[@]}"
  elif [[ "$OS_FAMILY" == "rhel" ]]; then
    dnf -y install "${pkgs[@]}" || yum -y install "${pkgs[@]}"
  else
    err "Unsupported OS family for package install."
    exit 1
  fi
}

service_enable_now() {
  local svc="$1"
  systemctl enable --now "$svc" >/dev/null 2>&1 || true
}

backup_file() {
  local f="$1"
  if [[ -f "$f" ]]; then
    cp -a "$f" "${f}.bak.$(date +%F_%H%M%S)"
    ok "Backed up $f"
  fi
}

ensure_user() {
  local username="$1"
  if id "$username" >/dev/null 2>&1; then
    ok "User '$username' already exists"
    return 0
  fi
  useradd -m -s /bin/bash "$username"
  ok "Created user '$username'"
  passwd "$username"
}

grant_sudo() {
  local username="$1"
  if [[ "$OS_FAMILY" == "debian" ]]; then
    usermod -aG sudo "$username"
    ok "Added '$username' to sudo group"
  else
    usermod -aG wheel "$username"
    ok "Added '$username' to wheel group"
  fi
}

detect_ssh_service() {
  if systemctl list-unit-files | grep -qE '^sshd\.service'; then
    SSH_SVC="sshd"
  else
    SSH_SVC="ssh"
  fi
}

restart_ssh() {
  systemctl restart "$SSH_SVC"
  ok "Restarted $SSH_SVC"
}

safe_edit_sshd_config() {
  local ssh_port="$1"
  local allow_user="$2"
  local enable_allowusers="$3"
  local disable_password_auth="$4"

  local cfg="/etc/ssh/sshd_config"
  backup_file "$cfg"

  # Ensure file exists
  touch "$cfg"

  # Helper to set or append a key
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

  if [[ -n "$ssh_port" ]]; then
    set_sshd_option "Port" "$ssh_port"
  fi

  if [[ "$disable_password_auth" == "yes" ]]; then
    set_sshd_option "PasswordAuthentication" "no"
  fi

  if [[ "$enable_allowusers" == "yes" && -n "$allow_user" ]]; then
    set_sshd_option "AllowUsers" "$allow_user"
  fi

  # Validate config before restart
  if sshd -t >/dev/null 2>&1; then
    ok "sshd_config validated OK"
  else
    err "sshd_config failed validation. Restoring backup."
    # Restore most recent backup
    local lastbak
    lastbak="$(ls -1t /etc/ssh/sshd_config.bak.* 2>/dev/null | head -n1 || true)"
    if [[ -n "$lastbak" ]]; then
      cp -a "$lastbak" /etc/ssh/sshd_config
      warn "Restored from $lastbak"
    fi
    exit 1
  fi
}

enable_auto_updates() {
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

  cat >/etc/fail2ban/jail.d/bearfortify.local <<'EOF'
[sshd]
enabled = true
findtime = 10m
maxretry = 5
bantime = 1h
EOF

  service_enable_now fail2ban
  ok "Fail2ban enabled"
}

install_lynis() {
  if [[ "$OS_FAMILY" == "debian" ]]; then
    pkg_install lynis
  else
    pkg_install epel-release || true
    pkg_install lynis
  fi
  ok "Lynis installed (run: sudo lynis audit system)"
}

main() {
  title
  require_root
  detect_os
  detect_ssh_service

  if [[ "$OS_FAMILY" == "unknown" ]]; then
    err "Unsupported distro. BearFortify supports Ubuntu/Debian and RHEL/Rocky/Alma."
    exit 1
  fi

  ok "Detected OS family: $OS_FAMILY"
  ok "Detected SSH service: $SSH_SVC"

  echo
  echo -e "${COLOR_BOLD}Step 1 — Choose your settings${COLOR_RESET}"

  HARDEN_USER="$(ask_input "Admin username to ensure exists" "bear")"
  SSH_PORT="$(ask_input "SSH port" "22")"

  ENABLE_ALLOWUSERS="no"
  if ask_yes_no "Restrict SSH logins to ONLY this user via AllowUsers?" "y"; then
    ENABLE_ALLOWUSERS="yes"
  fi

  DISABLE_PASSWORD_AUTH="no"
  if ask_yes_no "Disable SSH password authentication (keys only)?" "y"; then
    DISABLE_PASSWORD_AUTH="yes"
  else
    warn "Keeping password auth enabled — okay for learning, not ideal for prod."
  fi

  echo
  echo -e "${COLOR_BOLD}Step 2 — Apply safe baseline hardening${COLOR_RESET}"

  if ask_yes_no "Update packages now?" "y"; then
    if [[ "$OS_FAMILY" == "debian" ]]; then
      apt-get update -y
      apt-get upgrade -y
      apt-get autoremove -y
    else
      dnf -y update || yum -y update
    fi
    ok "Packages updated"
  fi

  if ask_yes_no "Ensure admin user '$HARDEN_USER' exists and has sudo?" "y"; then
    ensure_user "$HARDEN_USER"
    grant_sudo "$HARDEN_USER"
  fi

  ok "Hardening SSH settings"
  safe_edit_sshd_config "$SSH_PORT" "$HARDEN_USER" "$ENABLE_ALLOWUSERS" "$DISABLE_PASSWORD_AUTH"

  warn "IMPORTANT: If you changed SSH port, make sure your cloud firewall/security group allows it."
  restart_ssh


  echo
  echo -e "${COLOR_BOLD}Step 3 — Auto updates${COLOR_RESET}"
  if ask_yes_no "Enable automatic security updates?" "y"; then
    enable_auto_updates
  fi

  echo
  echo -e "${COLOR_BOLD}Step 4 — Optional tools${COLOR_RESET}"
  if ask_yes_no "Install + enable Fail2ban (SSH brute-force blocking)?" "y"; then
    install_fail2ban
  fi

  if ask_yes_no "Install Lynis (security audit tool)?" "y"; then
    install_lynis
  fi

  echo
  echo -e "${COLOR_BOLD}🎉 BearFortify complete${COLOR_RESET}"
  echo
  echo "Next steps:"
  echo "  1) In a NEW terminal, test SSH login:"
  echo "       ssh -p ${SSH_PORT} ${HARDEN_USER}@YOUR_SERVER_IP"
  echo
  echo "  2) Verify SSH config:"
  echo "       sudo sshd -T | egrep 'port|permitrootlogin|passwordauthentication|allowusers'"
  echo
  echo "  3) Audit your system:"
  echo "       sudo lynis audit system"
  echo
  ok "Stay safe, little Linux bear 🐻"
}

main "$@"
