---
source: "common/server/linux-server-hardening.md"
title: "Linux Server Hardening"
heading: "3. SELinux / AppArmor"
category: "common-vuln"
language: "common"
severity: "high"
tags: [apparmor, common-vuln, configuration, firewall, hardening, selinux, system, table]
chunk: 5/12
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