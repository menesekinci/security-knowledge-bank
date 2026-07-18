---
source: "common/cloud-security/docker-security.md"
title: "Docker Security"
heading: "5. Rootless Mode"
category: "cloud-security"
language: "common"
severity: "medium"
tags: [cloud-security, containers, contexts, host, mounts, overview, privileged, security, table]
chunk: 8/11
---

## 5. Rootless Mode

Rootless Docker runs the daemon without root privileges, adding a significant security layer. It has been available since Docker 19.03.

### Setup Rootless Docker

```bash
# Install rootless Docker (doesn't require root)
dockerd-rootless-setuptool.sh install

# Run containers in rootless mode
docker context use rootless
docker run --rm hello-world

# Verify rootless
docker info --format '{{.SecurityOptions}}'
# Should show "name=rootless"
```

### Rootless Limitations

```bash
# Rootless mode restrictions:
# - No '--privileged' (blocked)
# - No port binding < 1024 without net.ipv4.ip_unprivileged_port_start
# - No overlay network by default
# - Limited cgroup support

# Workaround for binding port 80:
sudo setcap cap_net_bind_service=ep $(which rootlesskit)
docker run -p 80:8080 nginx  # Now works
```

### Compare: Rootless vs Rootful

| Feature | Rootful | Rootless |
|---|---|---|
| Container escape to root on host | Possible | Not possible |
| `--privileged` | Allowed | Blocked |
| Bind ports < 1024 | Allowed | Requires capability |
| AppArmor/SELinux | Full support | Limited |
| Overlay network | Supported | Slirp4netns |

---