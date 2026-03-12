<!-- # Server Fortress -->

![](Server-Fortress.png)

Hardening a new Linux server is tedious and error-prone — SSH config, firewall rules, auto-updates, brute-force protection. Easy to miss a step; easy to lock yourself out.

**BearFortify** is an interactive bash script that walks you through safe, step-by-step server hardening on Ubuntu/Debian and RHEL/Rocky/Alma. It backs up configs before touching them, validates SSH config before restarting, and prompts before every change.

Covers:

- SSH hardening (port, key-only auth, AllowUsers, PermitRootLogin)
- Firewall setup (UFW or firewalld)
- Automatic security updates
- Fail2ban for SSH brute-force blocking
- Lynis security audit tool

## Example Output

```
🐻 BearFortify — Safe Linux Server Hardening
------------------------------------------------
✅ Detected OS family: debian
✅ Detected SSH service: ssh

Step 1 — Choose your settings
Admin username to ensure exists [bear]:
SSH port [22]: 2222
...
✅ sshd_config validated OK
✅ Restarted ssh
✅ UFW enabled
🎉 BearFortify complete
```

## Installation

```bash
git clone https://github.com/tdiprima/Server-Fortress.git
cd Server-Fortress
```

## Usage

```bash
sudo bash src/fortify.sh
```

For RHEL/Rocky/Alma:

```bash
sudo bash src/fortify-rhel.sh
```

Use without firewall setup:

```bash
sudo bash src/fortify-no-firewall.sh
```

## ⚠️ Disclaimer

This script makes system-level security changes including SSH configuration, firewall rules, user accounts, and update settings. While it includes safeguards (backups, validation checks, and interactive prompts), **you are responsible for reviewing changes before applying them to any system**.

Use at your own risk. The author is not liable for:

* Loss of access to a server
* Service disruption or downtime
* Misconfiguration in custom or non-standard environments
* Etc.

Always test on a non-production system first and verify SSH access in a new session before closing your current one.

<br>
