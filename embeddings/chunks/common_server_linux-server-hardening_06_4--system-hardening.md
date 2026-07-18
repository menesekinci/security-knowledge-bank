---
source: "common/server/linux-server-hardening.md"
title: "Linux Server Hardening"
heading: "4. System Hardening"
category: "common-vuln"
language: "common"
severity: "high"
tags: [apparmor, common-vuln, configuration, firewall, hardening, selinux, system, table]
chunk: 6/12
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