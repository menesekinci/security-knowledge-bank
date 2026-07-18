---
source: "common/server/linux-server-hardening.md"
title: "Linux Server Hardening"
heading: "1. SSH Hardening"
category: "common-vuln"
language: "common"
severity: "high"
tags: [apparmor, common-vuln, configuration, firewall, hardening, selinux, system, table]
chunk: 3/12
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