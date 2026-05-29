# Server Fortress

Declarative Linux server hardening as code — one config file, one command, repeatable security.

![Server Fortress](Server-Fortress.png)

## Every New Server Ships Wide Open

A fresh Linux server allows root SSH login, has no firewall rules, no brute-force protection, and no automatic security updates. The standard response is a 45-minute checklist of manual commands that nobody runs the same way twice. When you have five servers, that's an afternoon. When you have fifty, settings drift, steps get skipped, and the server you forgot about is the one that gets compromised.

Existing tools like Ansible solve this at scale, but they require inventory files, YAML playbooks, and a control node — infrastructure to manage your infrastructure. For teams that just need their servers locked down consistently, that's overhead they don't need.

## Hardening That Works Like Infrastructure as Code

Server Fortress takes a different approach: declare your security posture in a plain config file, and the tool converges the system to match — every time, on every run.

**`fortify.sh`** reads a simple key-value config and applies a security baseline across Ubuntu, Debian, RHEL, Rocky, and Alma Linux:

- Creates an admin user with sudo access
- Hardens SSH (disables root login, enforces key-only auth, restricts allowed users)
- Configures the OS firewall (UFW or firewalld) with only the ports you declare
- Installs Fail2ban for SSH brute-force protection
- Enables automatic security updates
- Installs Lynis for ongoing security auditing

Every operation is **idempotent** — run it once or ten times, you get the same result. It tracks state in `/var/lib/fortify/state.conf`, so it knows what it owns. Change `INSTALL_FAIL2BAN=yes` to `no`, re-run, and Fail2ban gets cleanly removed. Change `SSH_PORT` from `22` to `2222`, and the old firewall rule gets replaced. This is full lifecycle management: add, modify, and remove.

**`lynis-report.sh`** parses Lynis audit results into a prioritized, human-readable summary — in the terminal or as a standalone HTML report — so you can see exactly what to fix next.

## Concrete Example

Start with the config:

```bash
cp src/fortify.conf.example fortify.conf
```

```bash
# fortify.conf
ADMIN_USER="deploy"
SSH_PORT="2222"
WEB_SERVER="yes"
SSH_ALLOW_USERS="yes"
SSH_DISABLE_PASSWORD="yes"
CONFIGURE_FIREWALL="yes"
ENABLE_AUTO_UPDATES="yes"
INSTALL_FAIL2BAN="yes"
INSTALL_LYNIS="yes"
```

Apply it:

```
$ sudo bash src/fortify.sh --config fortify.conf

[OK]    OS: debian | SSH: ssh
[OK]    Packages updated
[OK]    User 'deploy' already exists
[OK]    User 'deploy' already in sudo group
[OK]    SSH hardened and restarted
[OK]    UFW configured
[OK]    Auto updates enabled (unattended-upgrades)
[OK]    Fail2ban configured and enabled
[OK]    Lynis installed
[OK]    State saved to /var/lib/fortify/state.conf
```

Later, decide this server no longer needs to be a web server. Change one line:

```bash
WEB_SERVER="no"
```

Re-run. Fortify removes the HTTP/HTTPS firewall rules and leaves everything else untouched:

```
[DEL]   Removed stale HTTP/HTTPS rules
[OK]    UFW configured
```

## Usage

### Hardening

```bash
# Preview what would change
sudo bash src/fortify.sh --config fortify.conf --dry-run

# Apply the configuration
sudo bash src/fortify.sh --config fortify.conf

# Check for drift between config and live system
sudo bash src/fortify.sh --config fortify.conf --drift

# Revert everything fortify applied
sudo bash src/fortify.sh --rollback
```

### Security Audit Reports

```bash
# Run a fresh Lynis scan and print a summary
sudo bash src/lynis-report.sh

# Parse an existing scan without re-running
sudo bash src/lynis-report.sh --report-only

# Generate an HTML report
sudo bash src/lynis-report.sh --html
```

### Supported Platforms

- Ubuntu / Debian
- RHEL / Rocky / Alma Linux

## License

[MIT](LICENSE)
