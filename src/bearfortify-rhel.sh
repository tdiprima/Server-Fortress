#!/usr/bin/env bash
set -euo pipefail

# BearFortify-RHEL — Harden RHEL 7.x and RHEL 9.x servers (interactive)
# Supports: RHEL 7.9, RHEL 9.x (Rocky/Alma also work)
# Author: Bear energy 🐻

COLOR_BOLD="\033[1m"
COLOR_GREEN="\033[32m"
COLOR_YELLOW="\033[33m"
COLOR_RED="\033[31m"
COLOR_RESET="\033[0m"

ok()    { echo -e "${COLOR_GREEN}✅ $*${COLOR_RESET}"; }
warn()  { echo -e "${COLOR_YELLOW}⚠️  $*${COLOR_RESET}"; }
err()   { echo -e "${COLOR_RED}❌ $*${COLOR_RESET}"; }

title() {
  echo
  echo -e "${COLOR_BOLD}🐻 BearFortify-RHEL — RHEL 7 / RHEL 9 Server Hardening${COLOR_RESET}"
  echo "--------------------------------------------------------"
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
      n|N|no|NO)   return 1 ;;
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

# ── OS Detection ────────────────────────────────────────────────────────────

detect_os() {
  if [[ ! -r /etc/os-release ]]; then
    err "/etc/os-release not found. Cannot detect OS."
    exit 1
  fi

  # shellcheck disable=SC1091
  source /etc/os-release
  OS_ID="${ID:-unknown}"
  OS_LIKE="${ID_LIKE:-}"
  OS_VERSION_ID="${VERSION_ID:-0}"
  RHEL_MAJOR="${OS_VERSION_ID%%.*}"   # e.g. "7" or "9"

  # Confirm this is a supported RHEL-family OS
  if [[ "$OS_ID" == "rhel" || "$OS_ID" == "centos" || \
        "$OS_ID" == "rocky" || "$OS_ID" == "almalinux" || \
        "$OS_LIKE" == *"rhel"* || "$OS_LIKE" == *"fedora"* ]]; then
    : # supported
  else
    err "Unsupported OS: $OS_ID. This script is for RHEL/CentOS/Rocky/Alma only."
    exit 1
  fi

  if [[ "$RHEL_MAJOR" -ne 7 && "$RHEL_MAJOR" -ne 9 ]]; then
    warn "This script was tested on RHEL 7 and RHEL 9. Detected major version: $RHEL_MAJOR. Proceeding anyway."
  fi
}

# ── Package Management ───────────────────────────────────────────────────────

pkg_install() {
  local pkgs=("$@")
  if [[ "$RHEL_MAJOR" -ge 8 ]]; then
    dnf -y install "${pkgs[@]}"
  else
    yum -y install "${pkgs[@]}"
  fi
}

pkg_update() {
  if [[ "$RHEL_MAJOR" -ge 8 ]]; then
    dnf -y update
  else
    yum -y update
  fi
}

# ── EPEL Setup ───────────────────────────────────────────────────────────────
# RHEL 7:  yum install epel-release (simple)
# RHEL 9:  must enable codeready-builder + install EPEL RPM directly from Fedora
#          because 'dnf install epel-release' alone is unreliable on true RHEL 9

enable_epel() {
  if rpm -q epel-release &>/dev/null; then
    ok "EPEL already enabled"
    return 0
  fi

  if [[ "$RHEL_MAJOR" -ge 8 ]]; then
    ok "Enabling CodeReady Linux Builder repo (required for EPEL on RHEL 9)..."
    # subscription-manager is only present on real RHEL (not Rocky/Alma)
    if command -v subscription-manager &>/dev/null; then
      local arch
      arch="$(uname -m)"
      subscription-manager repos \
        --enable "codeready-builder-for-rhel-${RHEL_MAJOR}-${arch}-rpms" 2>/dev/null || \
        warn "Could not enable codeready-builder via subscription-manager (may be OK on Rocky/Alma)"
    fi
    # Install EPEL from Fedora Project directly — works for RHEL, Rocky, Alma
    dnf -y install \
      "https://dl.fedoraproject.org/pub/epel/epel-release-latest-${RHEL_MAJOR}.noarch.rpm" || \
      dnf -y install epel-release   # fallback for Rocky/Alma where this works fine
    ok "EPEL enabled (RHEL ${RHEL_MAJOR})"
  else
    yum -y install epel-release
    ok "EPEL enabled (RHEL 7)"
  fi
}

# ── Filesystem / User Helpers ────────────────────────────────────────────────

backup_file() {
  local f="$1"
  if [[ -f "$f" ]]; then
    cp -a "$f" "${f}.bak.$(date +%F_%H%M%S)"
    ok "Backed up $f"
  fi
}

ensure_user() {
  local username="$1"
  if id "$username" &>/dev/null; then
    ok "User '$username' already exists"
    return 0
  fi
  useradd -m -s /bin/bash "$username"
  ok "Created user '$username'"
  passwd "$username"
}

grant_sudo() {
  local username="$1"
  usermod -aG wheel "$username"
  ok "Added '$username' to wheel group (sudo)"
}

# ── SELinux Helpers ──────────────────────────────────────────────────────────

selinux_allow_ssh_port() {
  local port="$1"
  [[ "$port" -eq 22 ]] && return 0   # Port 22 is already allowed; nothing to do

  # Ensure semanage is available
  if ! command -v semanage &>/dev/null; then
    ok "Installing policycoreutils-python-utils (provides semanage)..."
    pkg_install policycoreutils-python-utils
  fi

  local current_mode
  current_mode="$(getenforce 2>/dev/null || echo 'Disabled')"

  if [[ "$current_mode" == "Disabled" ]]; then
    warn "SELinux is Disabled — skipping semanage step"
    return 0
  fi

  ok "Telling SELinux to allow sshd on port $port..."
  # If port is already labeled ssh_port_t, -a will fail; use -m to modify instead
  if semanage port -l | grep -q "ssh_port_t.*tcp.*\b${port}\b"; then
    ok "SELinux already allows port $port for SSH"
  else
    semanage port -a -t ssh_port_t -p tcp "$port" 2>/dev/null || \
    semanage port -m -t ssh_port_t -p tcp "$port"
    ok "SELinux port label added for tcp/$port"
  fi
}

# ── SSH Hardening ────────────────────────────────────────────────────────────

safe_edit_sshd_config() {
  local ssh_port="$1"
  local allow_user="$2"
  local enable_allowusers="$3"
  local disable_password_auth="$4"

  local cfg="/etc/ssh/sshd_config"
  backup_file "$cfg"
  touch "$cfg"

  # Set or replace a directive in sshd_config (case-insensitive key match)
  set_sshd_option() {
    local key="$1"
    local value="$2"
    if grep -qiE "^\s*${key}\s+" "$cfg"; then
      sed -i -E "s|^\s*${key}\s+.*|${key} ${value}|I" "$cfg"
    else
      echo "${key} ${value}" >> "$cfg"
    fi
  }

  set_sshd_option "PermitRootLogin"       "no"
  set_sshd_option "MaxAuthTries"          "3"
  set_sshd_option "LoginGraceTime"        "30"
  set_sshd_option "X11Forwarding"         "no"
  set_sshd_option "PermitEmptyPasswords"  "no"
  set_sshd_option "PubkeyAuthentication"  "yes"
  set_sshd_option "UseDNS"               "no"     # faster logins on RHEL
  set_sshd_option "GSSAPIAuthentication" "no"      # disable Kerberos noise if unused

  if [[ -n "$ssh_port" ]]; then
    set_sshd_option "Port" "$ssh_port"
    # Must update SELinux BEFORE restarting sshd
    selinux_allow_ssh_port "$ssh_port"
  fi

  if [[ "$disable_password_auth" == "yes" ]]; then
    set_sshd_option "PasswordAuthentication" "no"
  fi

  if [[ "$enable_allowusers" == "yes" && -n "$allow_user" ]]; then
    set_sshd_option "AllowUsers" "$allow_user"
  fi

  # Validate before restart
  if sshd -t &>/dev/null; then
    ok "sshd_config validated OK"
  else
    err "sshd_config failed validation — restoring backup"
    local lastbak
    lastbak="$(ls -1t /etc/ssh/sshd_config.bak.* 2>/dev/null | head -n1 || true)"
    [[ -n "$lastbak" ]] && cp -a "$lastbak" "$cfg" && warn "Restored from $lastbak"
    exit 1
  fi
}

restart_ssh() {
  systemctl restart sshd
  ok "sshd restarted"
}

# ── Firewall ─────────────────────────────────────────────────────────────────
# RHEL 7 and 9 both use firewalld; backend differs (iptables vs nftables)
# but firewall-cmd interface is identical — no version branching needed here.

configure_firewalld() {
  local ssh_port="$1"
  local allow_http="$2"
  local allow_https="$3"

  pkg_install firewalld
  systemctl enable --now firewalld

  # Remove the generic 'ssh' service rule if we're using a non-standard port,
  # so we don't leave port 22 open by accident.
  if [[ "$ssh_port" -ne 22 ]]; then
    firewall-cmd --permanent --remove-service=ssh &>/dev/null || true
    firewall-cmd --permanent --add-port="${ssh_port}/tcp"
    ok "Firewalld: opened custom SSH port $ssh_port/tcp (removed default port 22 service)"
  else
    firewall-cmd --permanent --add-service=ssh &>/dev/null || true
    ok "Firewalld: SSH port 22 allowed"
  fi

  [[ "$allow_http"  == "yes" ]] && firewall-cmd --permanent --add-service=http  && ok "Firewalld: HTTP allowed"
  [[ "$allow_https" == "yes" ]] && firewall-cmd --permanent --add-service=https && ok "Firewalld: HTTPS allowed"

  firewall-cmd --reload
  ok "Firewalld rules reloaded"
  firewall-cmd --list-all
}

# ── Auto Updates ─────────────────────────────────────────────────────────────
# RHEL 7 → yum-cron
# RHEL 9 → dnf-automatic

enable_auto_updates() {
  if [[ "$RHEL_MAJOR" -ge 8 ]]; then
    pkg_install dnf-automatic
    # Configure security-only updates
    local cfg="/etc/dnf/automatic.conf"
    if [[ -f "$cfg" ]]; then
      sed -i 's/^upgrade_type\s*=.*/upgrade_type = security/' "$cfg"
      sed -i 's/^apply_updates\s*=.*/apply_updates = yes/' "$cfg"
    fi
    systemctl enable --now dnf-automatic.timer
    ok "Auto security updates enabled via dnf-automatic.timer"
  else
    pkg_install yum-cron
    local cfg="/etc/yum/yum-cron.conf"
    if [[ -f "$cfg" ]]; then
      sed -i 's/^update_cmd\s*=.*/update_cmd = security/' "$cfg"
      sed -i 's/^apply_updates\s*=.*/apply_updates = yes/' "$cfg"
    fi
    systemctl enable --now yum-cron
    ok "Auto security updates enabled via yum-cron"
  fi
}

# ── Fail2ban ─────────────────────────────────────────────────────────────────
# Needs EPEL on both RHEL 7 and 9.
# On RHEL 9 also install fail2ban-firewalld so it uses firewalld as ban backend.

# install_fail2ban() {
#   enable_epel

#   if [[ "$RHEL_MAJOR" -ge 8 ]]; then
#     pkg_install fail2ban fail2ban-firewalld fail2ban-server
#   else
#     pkg_install fail2ban fail2ban-server
#   fi

#   # Copy jail.conf → jail.local so upgrades don't clobber our settings
#   if [[ -f /etc/fail2ban/jail.conf && ! -f /etc/fail2ban/jail.local ]]; then
#     cp -a /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
#   fi

#   mkdir -p /etc/fail2ban/jail.d

#   # On RHEL 9+, fail2ban-firewalld ships a drop-in that sets
#   # banaction = firewallcmd-rich-rules — install it if not already there
#   if [[ "$RHEL_MAJOR" -ge 8 ]]; then
#     cat >/etc/fail2ban/jail.d/bearfortify.local <<EOF
# [DEFAULT]
# banaction = firewallcmd-rich-rules[actiontype=<multiport>]
# banaction_allports = firewallcmd-rich-rules[actiontype=<allports>]

# [sshd]
# enabled  = true
# port     = ${SSH_PORT}
# logpath  = /var/log/secure
# backend  = systemd
# findtime = 10m
# maxretry = 5
# bantime  = 1h
# EOF
#   else
#     # RHEL 7 — iptables backend is fine
#     cat >/etc/fail2ban/jail.d/bearfortify.local <<EOF
# [sshd]
# enabled  = true
# port     = ${SSH_PORT}
# logpath  = /var/log/secure
# findtime = 10m
# maxretry = 5
# bantime  = 1h
# EOF
#   fi

#   systemctl enable --now fail2ban
#   ok "Fail2ban enabled"
# }

# ── Lynis ────────────────────────────────────────────────────────────────────

install_lynis() {
  enable_epel
  pkg_install lynis
  ok "Lynis installed — run: sudo lynis audit system"
}

# ── Additional RHEL Hardening ────────────────────────────────────────────────
# Things that matter on RHEL that the original script didn't address

apply_rhel_extras() {
  ok "Applying additional RHEL hardening tweaks..."

  # 1. Disable core dumps
  if ! grep -q "hard core" /etc/security/limits.conf; then
    echo "* hard core 0" >> /etc/security/limits.conf
    ok "Core dumps disabled in limits.conf"
  fi

  # 2. Set more restrictive umask in /etc/profile (if not already set)
  if ! grep -q "umask 027" /etc/profile; then
    echo "umask 027" >> /etc/profile
    ok "umask 027 set in /etc/profile"
  fi

  # 3. Ensure auditd is installed and running
  pkg_install audit
  systemctl enable --now auditd
  ok "auditd enabled"

  # 4. Disable unused/risky services (silently skip if not present)
  local risky_svcs=(avahi-daemon cups rpcbind nfs-server)
  for svc in "${risky_svcs[@]}"; do
    if systemctl is-active --quiet "$svc" 2>/dev/null; then
      warn "Disabling $svc (not needed on most servers)"
      systemctl disable --now "$svc" 2>/dev/null || true
    fi
  done
}

# ── Main ─────────────────────────────────────────────────────────────────────

main() {
  title
  require_root
  detect_os

  ok "Detected: ${PRETTY_NAME:-${OS_ID} ${OS_VERSION_ID}}"
  ok "RHEL major version: $RHEL_MAJOR"

  echo
  echo -e "${COLOR_BOLD}Step 1 — Choose your settings${COLOR_RESET}"

  HARDEN_USER="$(ask_input "Admin username to create/ensure" "bear")"
  SSH_PORT="$(ask_input "SSH port" "22")"

  ALLOW_HTTP="no"
  ALLOW_HTTPS="no"
  if ask_yes_no "Is this a web server (open HTTP/HTTPS)?" "n"; then
    ALLOW_HTTP="yes"
    ALLOW_HTTPS="yes"
  fi

  ENABLE_ALLOWUSERS="no"
  if ask_yes_no "Restrict SSH to ONLY this user via AllowUsers?" "y"; then
    ENABLE_ALLOWUSERS="yes"
  fi

  DISABLE_PASSWORD_AUTH="no"
  if ask_yes_no "Disable SSH password auth (keys only)?" "y"; then
    DISABLE_PASSWORD_AUTH="yes"
  else
    warn "Keeping password auth enabled — fine for learning, not recommended for prod."
  fi

  # ── Step 2: Packages ──────────────────────────────────────────────────────
  echo
  echo -e "${COLOR_BOLD}Step 2 — Update packages${COLOR_RESET}"

  if ask_yes_no "Run full system update now?" "y"; then
    pkg_update
    ok "Packages updated"
  fi

  # ── Step 3: User ──────────────────────────────────────────────────────────
  echo
  echo -e "${COLOR_BOLD}Step 3 — Admin user${COLOR_RESET}"

  if ask_yes_no "Ensure admin user '$HARDEN_USER' exists with sudo (wheel)?" "y"; then
    ensure_user "$HARDEN_USER"
    grant_sudo "$HARDEN_USER"
  fi

  # ── Step 4: SSH ───────────────────────────────────────────────────────────
  echo
  echo -e "${COLOR_BOLD}Step 4 — Harden SSH${COLOR_RESET}"

  safe_edit_sshd_config "$SSH_PORT" "$HARDEN_USER" "$ENABLE_ALLOWUSERS" "$DISABLE_PASSWORD_AUTH"

  warn "IMPORTANT: Open port $SSH_PORT in your cloud security group / firewall BEFORE reconnecting."
  warn "Test in a NEW terminal before closing this session!"

  if ask_yes_no "Restart sshd now?" "y"; then
    restart_ssh
  fi

  # ── Step 5: Firewall ──────────────────────────────────────────────────────
  echo
  echo -e "${COLOR_BOLD}Step 5 — Configure firewalld${COLOR_RESET}"

  if ask_yes_no "Configure firewalld now?" "y"; then
    configure_firewalld "$SSH_PORT" "$ALLOW_HTTP" "$ALLOW_HTTPS"
  else
    warn "Skipping firewalld config. Ensure your cloud firewall is configured."
  fi

  # ── Step 6: Auto Updates ──────────────────────────────────────────────────
  echo
  echo -e "${COLOR_BOLD}Step 6 — Auto updates${COLOR_RESET}"

  if ask_yes_no "Enable automatic security updates?" "y"; then
    enable_auto_updates
  fi

  # ── Step 7: Optional Tools ────────────────────────────────────────────────
  echo
  echo -e "${COLOR_BOLD}Step 7 — Optional tools${COLOR_RESET}"

  # if ask_yes_no "Install + enable Fail2ban (SSH brute-force blocking)?" "y"; then
  #   install_fail2ban
  # fi

  if ask_yes_no "Install Lynis (security audit tool)?" "y"; then
    install_lynis
  fi

  # ── Step 8: RHEL-specific extras ─────────────────────────────────────────
  echo
  echo -e "${COLOR_BOLD}Step 8 — RHEL-specific hardening${COLOR_RESET}"

  if ask_yes_no "Apply RHEL hardening extras (auditd, umask, disable risky services)?" "y"; then
    apply_rhel_extras
  fi

  # ── Done ──────────────────────────────────────────────────────────────────
  echo
  echo -e "${COLOR_BOLD}🎉 BearFortify-RHEL complete${COLOR_RESET}"
  echo
  echo "Next steps:"
  echo "  1) In a NEW terminal, test login:"
  echo "       ssh -p ${SSH_PORT} ${HARDEN_USER}@YOUR_SERVER_IP"
  echo
  echo "  2) Verify SSH settings:"
  echo "       sudo sshd -T | grep -E 'port|permitrootlogin|passwordauthentication|allowusers'"
  echo
  echo "  3) Check SELinux SSH port label:"
  echo "       semanage port -l | grep ssh"
  echo
  echo "  4) Audit with Lynis (if installed):"
  echo "       sudo lynis audit system"
  echo
  echo "  5) Check firewalld rules:"
  echo "       firewall-cmd --list-all"
  echo
  ok "Stay safe, RHEL bear 🐻"
}

main "$@"
