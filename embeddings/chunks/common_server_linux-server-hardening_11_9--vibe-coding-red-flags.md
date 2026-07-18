---
source: "common/server/linux-server-hardening.md"
title: "Linux Server Hardening"
heading: "9. Vibe-Coding Red Flags"
category: "common-vuln"
language: "common"
severity: "high"
tags: [apparmor, common-vuln, configuration, firewall, hardening, selinux, system, table]
chunk: 11/12
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