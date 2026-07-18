---
source: "common/server/linux-server-hardening.md"
title: "Linux Server Hardening"
heading: "7. Real Incidents"
category: "common-vuln"
language: "common"
severity: "high"
tags: [apparmor, common-vuln, configuration, firewall, hardening, selinux, system, table]
chunk: 9/12
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