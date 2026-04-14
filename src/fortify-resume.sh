#!/usr/bin/env bash
# set -euo pipefail

# fortify-resume.sh — Resume fortify AFTER SSH hardening step
# Use when fortify.sh failed/was interrupted at "Hardening SSH settings"
# Picks up at: restart_ssh → firewall → auto-updates → optional tools

COLOR_BOLD="\033[1m"
COLOR_GREEN="\033[32m"
COLOR_YELLOW="\033[33m"
COLOR_RED="\033[31m"
COLOR_RESET="\033[0m"

ok()   { echo -e "${COLOR_GREEN}✅ $*${COLOR_RESET}"; }
warn() { echo -e "${COLOR_YELLOW}⚠️  $*${COLOR_RESET}"; }
err()  { echo -e "${COLOR_RED}❌ $*${COLOR_RESET}"; }

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

detect_ssh_service() {
  if systemctl list-unit-files | grep -qE '^sshd\.service'; then
    SSH_SVC="sshd"
  else
    SSH_SVC="ssh"
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

restart_ssh() {
  systemctl restart "$SSH_SVC"
  ok "Restarted $SSH_SVC"
}

configure_firewall_ufw() {
  local ssh_port="$1"
  local allow_http="$2"
  local allow_https="$3"

  pkg_install ufw

  ufw --force reset
  ufw default deny incoming
  ufw default allow outgoing

  ufw allow "${ssh_port}/tcp"
  [[ "$allow_http" == "yes" ]] && ufw allow 80/tcp
  [[ "$allow_https" == "yes" ]] && ufw allow 443/tcp

  ufw --force enable
  ok "UFW enabled"
  ufw status verbose || true
}

configure_firewall_firewalld() {
  local ssh_port="$1"
  local allow_http="$2"
  local allow_https="$3"

  pkg_install firewalld
  service_enable_now firewalld

  firewall-cmd --permanent --add-port="${ssh_port}/tcp" >/dev/null
  [[ "$allow_http" == "yes" ]] && firewall-cmd --permanent --add-service=http >/dev/null
  [[ "$allow_https" == "yes" ]] && firewall-cmd --permanent --add-service=https >/dev/null

  firewall-cmd --reload >/dev/null
  ok "Firewalld configured"
  firewall-cmd --list-all || true
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

  cat >/etc/fail2ban/jail.d/userfortify.local <<'EOF'
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
  echo
  echo -e "${COLOR_BOLD}Fortify Resume — picking up after SSH hardening${COLOR_RESET}"
  echo "------------------------------------------------"

  require_root
  detect_os
  detect_ssh_service

  if [[ "$OS_FAMILY" == "unknown" ]]; then
    err "Unsupported distro. Fortify supports Ubuntu/Debian and RHEL/Rocky/Alma."
    exit 1
  fi

  ok "Detected OS family: $OS_FAMILY"
  ok "Detected SSH service: $SSH_SVC"

  # Collect only what the remaining steps need
  HARDEN_USER="$(ask_input "Admin username (used in next-steps summary)" "user")"
  SSH_PORT="$(ask_input "SSH port (the one you configured or kept)" "22")"

  ALLOW_HTTP="no"
  ALLOW_HTTPS="no"
  if ask_yes_no "Is this a web server (allow HTTP/HTTPS)?" "n"; then
    ALLOW_HTTP="yes"
    ALLOW_HTTPS="yes"
  fi

  # ── Resume point ────────────────────────────────────────────────────────────
  warn "IMPORTANT: If you changed SSH port, make sure your cloud firewall/security group allows it."
  restart_ssh

  echo
  echo -e "${COLOR_BOLD}Step 3 — Configure firewall${COLOR_RESET}"
  if ask_yes_no "Configure OS firewall now?" "y"; then
    if [[ "$OS_FAMILY" == "debian" ]]; then
      configure_firewall_ufw "$SSH_PORT" "$ALLOW_HTTP" "$ALLOW_HTTPS"
    else
      configure_firewall_firewalld "$SSH_PORT" "$ALLOW_HTTP" "$ALLOW_HTTPS"
    fi
  else
    warn "Skipping firewall configuration. (Cloud firewall alone can be OK but OS firewall is still recommended.)"
  fi

  echo
  echo -e "${COLOR_BOLD}Step 4 — Auto updates${COLOR_RESET}"
  if ask_yes_no "Enable automatic security updates?" "y"; then
    enable_auto_updates
  fi

  echo
  echo -e "${COLOR_BOLD}Step 5 — Optional tools${COLOR_RESET}"
  if ask_yes_no "Install + enable Fail2ban (SSH brute-force blocking)?" "y"; then
    install_fail2ban
  fi

  if ask_yes_no "Install Lynis (security audit tool)?" "y"; then
    install_lynis
  fi

  echo
  echo -e "${COLOR_BOLD}🎉 Fortify complete${COLOR_RESET}"
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
  ok "Stay safe"
}

main "$@"
