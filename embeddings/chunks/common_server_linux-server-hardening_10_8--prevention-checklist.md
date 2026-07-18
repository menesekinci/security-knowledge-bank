---
source: "common/server/linux-server-hardening.md"
title: "Linux Server Hardening"
heading: "8. Prevention Checklist"
category: "common-vuln"
language: "common"
severity: "high"
tags: [apparmor, common-vuln, configuration, firewall, hardening, selinux, system, table]
chunk: 10/12
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