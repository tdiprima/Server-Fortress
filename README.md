# 🐻 BearFortify

Interactive, "don't-lock-yourself-out" Linux server hardening script for **Ubuntu/Debian** and **RHEL/Rocky/Alma**.

## What it does

Runs a guided checklist that helps you quickly harden a fresh server:

- **Detects your distro family** (Debian-ish vs RHEL-ish)
- **Optionally updates packages**
- **Ensures an admin user exists** (creates it if missing) and **grants sudo**
- **Hardens SSH** (safely)
  - Disables **root login**
  - Optionally changes **SSH port**
  - Optionally enables **keys-only** (disables password auth)
  - Optionally restricts logins via `AllowUsers`
  - Sets sensible limits (MaxAuthTries, LoginGraceTime, etc.)
  - **Backs up** `/etc/ssh/sshd_config` before changes
  - **Validates** SSH config with `sshd -t` and restores backup if invalid
- **Configures firewall**
  - Debian: **UFW**
  - RHEL: **firewalld**
  - Opens SSH port (+ optional HTTP/HTTPS if you say it's a web server)
- **Enables automatic security updates**
  - Debian: `unattended-upgrades`
  - RHEL: `dnf-automatic`
- **Optional extras**
  - **Fail2ban** (SSH brute-force protection)
  - **Lynis** (security auditing tool)

## Why it's "safe-ish"

- Makes timestamped backups of SSH config
- Tests SSH config before restarting SSH
- Interactive prompts so you control what changes

## Usage

```bash
sudo bash bearfortify.sh
```

## After you run it (don't skip)

In a **new terminal** (so you don't lose access if you changed things):

```bash
ssh -p <PORT> <USER>@<SERVER_IP>
```

Check what SSH is actually using:

```bash
sudo sshd -T | egrep 'port|permitrootlogin|passwordauthentication|allowusers'
```

## Notes / gotchas

- If you change the SSH port, also update your **cloud firewall / security group**.
- If you disable password auth, make sure you have **SSH keys working first**.

## Supports

- ✅ Ubuntu / Debian
- ✅ RHEL / Rocky / Alma (and similar)

---

Stay safe, little Linux bear.

<br>
