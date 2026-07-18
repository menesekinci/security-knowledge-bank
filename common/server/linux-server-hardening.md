# Linux Server Hardening

> **Severity:** High  
> **CWE:** CWE-16 (Configuration), CWE-250 (Privilege Escalation), CWE-276 (Incorrect Default Permissions), CWE-778 (Insufficient Logging), CWE-362 (Race Condition)  
> **AI Generation Risk:** Medium — AI typically doesn't generate server configurations directly, but server hardening knowledge is essential for AI-deployed applications and infrastructure-as-code outputs.  
> **Last Updated:** 2025-07-17

---

## Table of Contents

1. [SSH Hardening](#1-ssh-hardening)
2. [Firewall Configuration](#2-firewall-configuration)
3. [SELinux / AppArmor](#3-selinux--apparmor)
4. [System Hardening](#4-system-hardening)
5. [Audit & Monitoring](#5-audit--monitoring)
6. [fail2ban Configuration](#6-fail2ban-configuration)
7. [Real Incidents](#7-real-incidents)
8. [Prevention Checklist](#8-prevention-checklist)
9. [Vibe-Coding Red Flags](#9-vibe-coding-red-flags)
10. [References](#10-references)

---

## 1. SSH Hardening

SSH is the most frequently attacked service on internet-facing Linux servers. Proper SSH hardening is the single highest-impact security measure you can take.

### 1.1 Disable Root Login

```ini
# /etc/ssh/sshd_config
PermitRootLogin no
```

Root login bypasses all audit trails — every action appears as root with no attribution. Use `sudo` for privilege elevation instead, which logs commands to `/var/log/auth.log` (or `journald`).

### 1.2 Key-Based Authentication Only

```ini
PasswordAuthentication no
ChallengeResponseAuthentication no
UsePAM no
```

Password authentication is susceptible to brute-force attacks. SSH keys provide cryptographic assurance that is exponentially harder to crack.

**Key strength recommendations:**
- **Ed25519** (preferred): `ssh-keygen -t ed25519 -a 100`
- **ECDSA** (secp384r1): `ssh-keygen -t ecdsa -b 384`
- **RSA**: minimum 4096 bits (legacy only; Ed25519 preferred)
- **Disable DSA** (insecure, key size limited to 1024 bits)

### 1.3 Custom Port vs. fail2ban

Moving SSH to a non-standard port (e.g., 2222) reduces log noise from automated scanners but is **not a security control** — dedicated attackers will find it. **Always pair with fail2ban** (see §6).

```ini
Port 2222
```

Combined approach:
- Use a non-standard port to reduce log volume
- Enforce fail2ban with aggressive bans after 3–5 failures
- Allow only specific users via `AllowUsers` (see §1.5)

### 1.4 Additional SSH Hardening

```ini
# /etc/ssh/sshd_config
Protocol 2
MaxAuthTries 3
MaxSessions 10
LoginGraceTime 30
ClientAliveInterval 300
ClientAliveCountMax 0
StrictModes yes
IgnoreRhosts yes
HostbasedAuthentication no
PermitEmptyPasswords no
```

### 1.5 Restrict by User and Group

```ini
AllowUsers alice bob deploy
AllowGroups ssh-users admins
```

DenyUsers and DenyGroups can also be used, but Allow-users/groups is more restrictive and preferred.

### 1.6 SSH Ciphers and MACs (Modern Hardening)

```ini
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
KexAlgorithms curve25519-sha256@libssh.org,diffie-hellman-group16-sha512
```

This configuration avoids the vulnerable CBC-mode ciphers and SHA-1-based MACs exploited by the Terrapin attack (CVE-2023-48795).

---

## 2. Firewall Configuration

### 2.1 Choose Your Tool

| Tool | Use Case | Complexity |
|------|----------|------------|
| `iptables` | Legacy, direct netfilter control | Medium |
| `nftables` | Modern replacement for iptables | Medium |
| `ufw` | Ubuntu's frontend for iptables | Low |
| `firewalld` | RHEL/CentOS/Fedora dynamic firewall | Low–Medium |

**Recommendation:** Use `nftables` on new deployments (default in Debian 11+, RHEL 9+). Use `ufw` for simplicity on single-purpose servers.

### 2.2 Default Deny Policy

```bash
# nftables
nft add rule inet filter input policy drop
nft add rule inet filter forward policy drop
nft add rule inet filter output policy accept
```

An explicit default-deny policy ensures that only intentionally exposed services are reachable.

### 2.3 Expose Only Necessary Ports

```bash
# Example: Web server
nft add rule inet filter input tcp dport { 80, 443 } accept
nft add rule inet filter input tcp dport 22 accept  # SSH (or custom port)
nft add rule inet filter input ct state established,related accept
```

**Never expose:** MongoDB (27017), Redis (6379), PostgreSQL (5432), MySQL (3306), Cassandra (9042), Kafka (9092), RabbitMQ (5672, 15672), Docker daemon (2375/2376), Elasticsearch (9200), or admin panels without VPN/tunnel.

### 2.4 Rate Limiting

```bash
# nftables rate limit (max 10 new connections per second on SSH)
nft add chain inet filter input '{ policy drop; }'
nft add rule inet filter input tcp dport 22 ct state new limit rate 10/second accept
nft add rule inet filter input tcp dport 22 ct state new log prefix "SSH RATE LIMIT: " drop

# connlimit (max 3 concurrent SSH connections from same source)
iptables -A INPUT -p tcp --dport 22 -m connlimit --connlimit-above 3 -j REJECT
```

---

## 3. SELinux / AppArmor

### 3.1 Mandatory Access Control (MAC)

Linux Discretionary Access Control (DAC) — the traditional user/group/other permissions — is insufficient containment against compromised processes. MAC systems provide a second layer of mandatory controls.

| Feature | SELinux | AppArmor |
|---------|---------|----------|
| Default in | RHEL/CentOS/Fedora, Android | Debian/Ubuntu, openSUSE |
| Model | Label-based (ctx on every object) | Path-based (profile per program) |
| Granularity | Very high (every file, port, capability) | Medium |
| Complexity | Higher learning curve | Simpler profiles |

### 3.2 Enforcing SELinux

```bash
# Check status
getenforce
sestatus

# Set enforcing (permanent: /etc/selinux/config)
setenforce 1

# Common website troubleshooting
grep "SELinux" /var/log/audit/audit.log
audit2allow -w -a  # What is being denied?
audit2allow -a -M mypolicy  # Generate custom policy module
semodule -i mypolicy.pp
```

### 3.3 Enforcing AppArmor

```bash
# Check status
aa-status

# Set enforce
aa-enforce /usr/sbin/nginx

# Generate profile from logs
aa-logprof

# Reload profiles
systemctl reload apparmor
```

### 3.4 Common Violations and Fixes

| Symptom | Diagnosis | Fix |
|---------|-----------|-----|
| Nginx returns 403 | `grep nginx /var/log/audit/audit.log` | `setsebool -P httpd_can_network_connect 1` |
| PHP can't write uploads | SELinux blocking file writes | `semanage fcontext -a -t httpd_sys_rw_content_t '/var/www/html/uploads(/.*)?'` |
| Custom web root not serving | Wrong file context | `restorecon -Rv /path/to/webroot` |
| AppArmor denying MySQL | Check `syslog` for `apparmor="DENIED"` | `aa-complain /usr/sbin/mysqld` (to troubleshoot), update profile |

### 3.5 When to Disable (and Why Not To)

**Never disable SELinux/AppArmor on a production server.** The CIS benchmark treats disabling SELinux/AppArmor as a finding. If a service breaks, use `audit2allow`/`aa-logprof` to generate targeted policies rather than disabling MAC entirely.

If you absolutely must troubleshoot, set to permissive mode temporarily:
```bash
setenforce 0   # Don't forget to re-enforce!
```

---

## 4. System Hardening

### 4.1 sysctl Security Settings

```ini
# /etc/sysctl.d/99-security.conf

# Kernel ASLR (Address Space Layout Randomization)
kernel.randomize_va_space = 2

# Reverse path filtering (anti-spoofing)
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Disable source packet routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0

# Disable ICMP redirects
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0

# Ignore broadcast pings
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Enable TCP SYN flood protection
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_syn_retries = 2

# Disable IPv6 if not needed (otherwise secure it)
net.ipv6.conf.all.disable_ipv6 = 1

# Hardened TCP stack
net.core.bpf_jit_harden = 2
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.perf_event_paranoid = 3
```

Apply with `sysctl -p /etc/sysctl.d/99-security.conf`.

### 4.2 Mount Options and File Permissions

**Secure `/tmp` (noexec, nosuid, nodev):**
```bash
# /etc/fstab
tmpfs /tmp tmpfs defaults,noexec,nosuid,nodev,size=2G 0 0
```

For systems where `/tmp` cannot be a ramdisk, bind-mount with restrictive options:
```bash
mount -o remount,noexec,nosuid,nodev /tmp
```

**Separate partitions for world-writable directories:**
```bash
# /etc/fstab
/var/tmp  /var/tmp  none  bind,noexec,nosuid,nodev  0  0
```

**Set restrictive umask:**
```bash
# /etc/profile or /etc/bash.bashrc
umask 027
```

This creates files with 640 (rw-r-----) and directories with 750 (rwxr-x---) by default.

### 4.3 Disable Unused Services

```bash
# List all listening services
ss -tlnp

# Disable and stop unnecessary services
systemctl disable --now cups.service   # CVE-2024-47176: cups-browsed binding to INADDR_ANY:631
systemctl disable --now avahi-daemon.service
systemctl disable --now rpcbind.service
systemctl disable --now bluetooth.service
systemctl disable --now isc-dhcp-server.service
systemctl disable --now telnet.socket
systemctl disable --now vsftpd.service   # If FTP not needed
systemctl disable --now dovecot.service  # If email not needed
```

### 4.4 Automatic Security Updates

**Ubuntu/Debian (unattended-upgrades):**
```bash
apt install unattended-upgrades
dpkg-reconfigure -plow unattended-upgrades
```

**Configuration at `/etc/apt/apt.conf.d/50unattended-upgrades`:**
```ini
Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}-security";
};
Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::MinimalSteps "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";
Unattended-Upgrade::Automatic-Reboot-Time "03:00";
```

**RHEL/CentOS (dnf-automatic):**
```bash
dnf install dnf-automatic
sed -i 's/apply_updates = no/apply_updates = yes/' /etc/dnf/automatic.conf
systemctl enable --now dnf-automatic.timer
```

**Critical:** Always test security updates in a staging environment first. The xz backdoor (CVE-2024-3094, CVSS 10.0) was distributed through an upstream tarball — supply-chain verification (e.g., `apt-key`, signed packages) is critical.

### 4.5 Kernel Hardening with sysfs

```bash
# Disable kernel module loading for non-root
kernel.modules_disabled = 0   # Set to 1 only after verifying all needed modules loaded
# Enable module signing (CONFIG_MODULE_SIG_FORCE)
# Prevent user namespaces (if not needed)
user.max_user_namespaces = 0
```

---

## 5. Audit & Monitoring

### 5.1 auditd Configuration

```bash
apt install auditd audispd-plugins
```

**Key audit rules (`/etc/audit/rules.d/audit.rules`):**
```ini
# Record all sudo/logind events
-w /var/log/auth.log -p wa -k auth_log
-w /etc/sudoers -p wa -k sudoers
-w /etc/sudoers.d/ -p wa -k sudoers

# Monitor privilege escalation binaries
-w /usr/bin/su -p x -k priv_esc
-w /usr/bin/sudo -p x -k priv_esc
-w /etc/shadow -p wa -k shadow
-w /etc/passwd -p wa -k passwd

# Monitor system configuration changes
-w /etc/ssh/sshd_config -p wa -k sshd
-w /etc/sysctl.conf -p wa -k sysctl
-w /etc/selinux/ -p wa -k selinux

# Time changes
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time_change

# Process and module loading
-w /sbin/insmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-w /sbin/rmmod -p x -k modules
```

### 5.2 Log Aggregation Options

| Tool | Description | Scale |
|------|-------------|-------|
| **logwatch** | Lightweight daily log summary via cron | Single server |
| **ossec** | Host-based IDS with agent/manager model | Small–medium |
| **Wazuh** | OSSEC fork with SIEM capabilities | Medium–enterprise |
| **syslog-ng/rsyslog** | Centralized log shipping | All scales |

**Minimal setup — logwatch:**
```bash
apt install logwatch
# Runs daily via cron; reports emailed to root
# Configure /usr/share/logwatch/default.conf/logwatch.conf
```

**Wazuh agent setup (recommended for production):**
```bash
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | apt-key add -
apt install wazuh-agent
sed -i 's/MANAGER_IP/10.0.0.2/' /var/ossec/etc/ossec.conf
systemctl enable --now wazuh-agent
```

### 5.3 File Integrity Monitoring

**AIDE (Advanced Intrusion Detection Environment):**
```bash
apt install aide
aideinit  # Creates /var/lib/aide/aide.db.new.gz
mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz

# Run daily check
aide --check  # Send output to monitoring
```

**Tripwire (alternative):**
```bash
apt install tripwire
twadmin --create-polfile /etc/tripwire/twpol.txt
tripwire --init
tripwire --check
```

**Monitoring approach for KPI-driven teams:** Use AIDE/Tripwire for file-level integrity verification. For real-time changes (devops/SRE), use `inotifywait` or osquery.

### 5.4 Systemd Journal Monitoring

```bash
# Check for authentication failures
journalctl -u ssh -p err --since "1 week ago"

# Check for service failures
journalctl -p err --since "24 hours ago"

# Persistent logging
mkdir -p /var/log/journal
systemctl restart systemd-journald
```

---

## 6. fail2ban Configuration

### 6.1 Base Configuration

```bash
apt install fail2ban
```

**`/etc/fail2ban/jail.local`:**
```ini
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 5
destemail = admin@example.com
action = %(action_mwl)s

[sshd]
enabled = true
port = ssh
logpath = %(sshd_log)s
maxretry = 3

# Web server: nginx
[nginx-http-auth]
enabled = true
logpath = /var/log/nginx/error.log
maxretry = 5

# Web server: Apache
[apache-auth]
enabled = true
logpath = /var/log/apache2/error.log
maxretry = 5

# WordPress brute force
[wordpress]
enabled = true
logpath = /var/log/nginx/access.log
maxretry = 10
findtime = 60
```

### 6.2 Custom Filters for Database Services

**PostgreSQL jail (`/etc/fail2ban/jail.d/postgresql.conf`):**
```ini
[postgresql]
enabled = true
filter = postgresql
logpath = /var/log/postgresql/postgresql-*.log
maxretry = 5
```

**MySQL/MariaDB jail:**
```ini
[mysqld-auth]
enabled = true
filter = mysqld-auth
logpath = /var/log/mysql/error.log
maxretry = 5
```

### 6.3 Whitelisting

```ini
[DEFAULT]
ignoreip = 127.0.0.1/8 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16
```

Always whitelist internal monitoring/management IPs.

---

## 7. Real Incidents

### 7.1 SSH Brute Force (CVE-2024-6387 — regreSSHion)

**CVE-2024-6387** (CVSS 8.1, HIGH) is a signal-handling race condition in OpenSSH's `sshd` — a regression of the 2006 `CVE-2006-5051`. An unauthenticated remote attacker can trigger it by failing to authenticate within a set time period, potentially achieving remote code execution as root.

**Impact:** Affects OpenSSH versions 8.5p1 through 9.7p1 on glibc-based Linux systems.

**Real-world exploitation:** Within 24 hours of the July 2024 disclosure, security researchers observed mass scanning for vulnerable SSH servers. Several botnets added exploit modules for CVE-2024-6387.

**Mitigation:**
```bash
# Check version
sshd -V

# Patch immediately
apt update && apt upgrade openssh-server

# Mitigation if patching is delayed:
# Set LoginGraceTime to 0 in sshd_config (prevents the race condition window)
# Though this opens a different DoS vector (unclosed connections)
```

### 7.2 Terrapin Attack (CVE-2023-48795)

**CVE-2023-48795** (CVSS 5.9, MEDIUM) is a prefix truncation attack against the SSH Binary Packet Protocol. By manipulating sequence numbers during the extension negotiation, an attacker positioned as a man-in-the-middle can downgrade or disable security features (e.g., keystroke timing obfuscation, `chaCha20-poly1305` integrity).

**Impact:** Affects all SSH implementations that use SHA-1-based MACs without strict key exchange ordering.

**Mitigation:**
```bash
# Update to OpenSSH >= 9.6
# Or apply countermeasure: disable SHA-1 HMACs in sshd_config:
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
```

### 7.3 Ubuntu Local Privilege Escalation (CVE-2023-32629)

**CVE-2023-32629** (CVSS 7.8, HIGH) — A bug in Ubuntu's kernel overlay filesystem (`overlayfs`) allowed unprivileged local users to achieve root privileges by bypassing permission checks in `ovl_copy_up_meta_inode_data`. This was actively exploited in the wild.

**Takeaway:** Even with SSH perfectly hardened, local privilege escalation from kernel bugs is a real threat. Regular kernel updates, restricted user shells, and MAC (SELinux/AppArmor) policies are essential defense-in-depth measures.

### 7.4 xz Utils Backdoor (CVE-2024-3094)

**CVE-2024-3094** (CVSS 10.0, CRITICAL) — A sophisticated supply-chain attack inserted malicious code into xz/liblzma upstream tarballs (versions 5.6.0 and 5.6.1). The backdoor modified `liblzma` functions to intercept SSH authentication via `systemd`, allowing the attacker to bypass `sshd` authentication entirely.

**Impact:** Potentially affected any system using `sshd` linked to the compromised `systemd` and `liblzma`.

**Takeaway:** This is the most severe example of why automatic updates without integrity verification are dangerous. Actions taken:
- Use signed packages from official repos only (verify GPG keys)
- Pin specific known-good package versions when possible
- Monitor CVE notifications for critical infrastructure dependencies

---

## 8. Prevention Checklist

- [ ] **SSH Hardened:** `PermitRootLogin no`, `PasswordAuthentication no`, key-based auth only (`ed25519` preferred)
- [ ] **SSH configured:** `MaxAuthTries 3`, `LoginGraceTime 30`, `StrictModes yes`, `IgnoreRhosts yes`
- [ ] **SSH restricted:** `AllowUsers` or `AllowGroups` configured
- [ ] **SSH ciphers/MACs:** Weak ciphers disabled, only modern AEAD and ETM MACs
- [ ] **Firewall default-deny:** All inbound traffic dropped except explicitly allowed ports
- [ ] **Rate limiting enabled:** `connlimit` / `nftables` rate limits on SSH and other sensitive services
- [ ] **SELinux/AppArmor:** Enforcing mode enabled, not set to permissive/disabled
- [ ] **Unused services disabled:** cups, avahi, rpcbind, bluetooth, telnet, and any unneeded daemons
- [ ] **Automatic security updates:** `unattended-upgrades` (Debian) or `dnf-automatic` (RHEL) configured
- [ ] **sysctl hardening:** `rp_filter=1`, `randomize_va_space=2`, `accept_source_route=0`, TCP syncookies enabled
- [ ] **`/tmp` hardened:** Mounted with `noexec,nosuid,nodev` options
- [ ] **`umask 027`:** Set as default for all users
- [ ] **`auditd` configured:** Rules monitoring auth, config changes, privilege escalation
- [ ] **File integrity monitoring:** AIDE or Tripwire initialized and scheduled
- [ ] **fail2ban configured:** SSH jail active, custom jails for HTTP auth, DB services where relevant
- [ ] **Log aggregation:** Centralized logging (syslog/rsyslog to remote server) or Wazuh agent installed
- [ ] **Kernel updated:** Running latest kernel with security patches, rebooted to apply if needed
- [ ] **`/etc/issue.net` banner:** No OS/version disclosure in pre-login banner
- [ ] **PAM configured:** `pam_tally2` or `pam_faillock` for account lockout
- [ ] **Kernel module signing:** Enforced (CONFIG_MODULE_SIG_FORCE) if applicable

---

## 9. Vibe-Coding Red Flags

Watch for these patterns when AI generates server configuration scripts or infrastructure code:

| Red Flag | Why It's Dangerous | Fix |
|----------|-------------------|-----|
| `PermitRootLogin yes` | Allows direct root SSH, bypassing audit trails | Change to `no` |
| `PasswordAuthentication yes` | Enables SSH brute force attacks | Change to `no` |
| No firewall rules | All services exposed to internet | Add default-deny firewall |
| SELinux disabled (`SELINUX=disabled`) | MAC protection removed | Set `enforcing` |
| `sysctl -w` without persistence | Settings lost on reboot | Use `/etc/sysctl.d/` |
| `ufw disable` in setup scripts | Firewall disabled for convenience | Remove the disable line |
| `chmod 777` on directories | World-writable files | Use minimal permissions (755/644) |
| Service exposed on `0.0.0.0` | Binds to all interfaces (often unintentional) | Bind to specific IP |
| No `Restart=` in systemd units | Service won't restart after crash | Add `Restart=on-failure` |
| Running setup scripts as root without `sudo` audit | No audit trail | Use `sudo` with logging |
| `apt-get install` without `--no-install-recommends` | Pulls unnecessary services | Add `--no-install-recommends` |
| Using containers with `--privileged` | Bypasses all security boundaries | Use granular capabilities |
| No log rotation configured | Logs fill disk, service fails | Configure `logrotate` |

---

## 10. References

- **CIS Benchmarks:** https://www.cisecurity.org/cis-benchmarks/ (Linux benchmarks for Ubuntu, RHEL, Debian)
- **Mozilla SSH Guidelines:** https://infosec.mozilla.org/guidelines/openssh
- **stribika/secure-secure-shell:** https://github.com/stribika/secure-secure-shell
- **Arch Linux Security:** https://wiki.archlinux.org/title/Security
- **OpenSSH Hardening Guide:** https://www.ssh-audit.com/hardening_guides.html
- **SELinux Project Wiki:** https://selinuxproject.org/page/Main_Page
- **AppArmor Wiki:** https://gitlab.com/apparmor/apparmor/-/wikis/home
- **NIST NVD — CVE-2024-6387 (regreSSHion):** https://nvd.nist.gov/vuln/detail/CVE-2024-6387
- **NIST NVD — CVE-2023-48795 (Terrapin):** https://nvd.nist.gov/vuln/detail/CVE-2023-48795
- **NIST NVD — CVE-2024-3094 (xz backdoor):** https://nvd.nist.gov/vuln/detail/CVE-2024-3094
- **NIST NVD — CVE-2023-32629 (Ubuntu overlayfs):** https://nvd.nist.gov/vuln/detail/CVE-2023-32629
- **NIST NVD — CVE-2024-47176 (CUPS):** https://nvd.nist.gov/vuln/detail/CVE-2024-47176
- **NIST NVD — CVE-2024-10963 (pam_access):** https://nvd.nist.gov/vuln/detail/CVE-2024-10963
- **fail2ban wiki:** https://github.com/fail2ban/fail2ban/wiki
- **AIDE:** https://aide.github.io/
- **Wazuh:** https://wazuh.com/
- **logwatch:** https://sourceforge.net/projects/logwatch/

---

> **Next:** See [`../mq/message-queue-security.md`](../mq/message-queue-security.md) for securing RabbitMQ, Kafka, and Redis PubSub.
