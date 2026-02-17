RHEL &mdash; `fail2ban` wouldn't install.

On a system with a locked SELinux policy, firewalld rate-limiting is actually a clean, native solution with no extra packages needed. It works by dropping connections from any IP that exceeds a threshold, which stops brute-force SSH attempts just like fail2ban would.

Run these commands one at a time:

```bash
# 1. Create a rich rule that limits SSH connection attempts to 3 per minute per source IP.
#    Any IP exceeding that gets dropped for 60 seconds.
sudo firewall-cmd --permanent --add-rich-rule='
  rule family="ipv4"
  service name="ssh"
  source address="0.0.0.0/0"
  limit value="3/m"
  accept'

# 2. Reload firewalld to apply the permanent rule
sudo firewall-cmd --reload

# 3. Verify the rule is in place
sudo firewall-cmd --list-rich-rules
```

You should see your rule echoed back in the last command. To test it's working:

```bash
# Watch firewalld's drop log in real time (Ctrl+C to stop)
sudo journalctl -f -u firewalld
```

A few things worth knowing about this approach compared to fail2ban. Firewalld rate-limiting is **stateless** — it slows attackers down by throttling connections rather than outright banning an IP after N failures. This means a patient attacker could still try indefinitely, just slowly (3 attempts per minute). Fail2ban would permanently ban after 5 failures.

<br>
