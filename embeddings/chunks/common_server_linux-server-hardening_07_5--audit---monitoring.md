---
source: "common/server/linux-server-hardening.md"
title: "Linux Server Hardening"
heading: "5. Audit & Monitoring"
category: "common-vuln"
language: "common"
severity: "high"
tags: [apparmor, common-vuln, configuration, firewall, hardening, selinux, system, table]
chunk: 7/12
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