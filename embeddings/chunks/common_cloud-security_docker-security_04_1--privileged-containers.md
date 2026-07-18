---
source: "common/cloud-security/docker-security.md"
title: "Docker Security"
heading: "1. Privileged Containers"
category: "cloud-security"
language: "common"
severity: "medium"
tags: [cloud-security, containers, contexts, host, mounts, overview, privileged, security, table]
chunk: 4/11
---

## 1. Privileged Containers

Running a container with `--privileged` grants all capabilities and removes all isolation, effectively running as root on the host.

### Vulnerable Docker Run

```bash
# VULNERABLE: Privileged container — full host access
docker run --privileged -v /:/host ubuntu bash
# Inside container:
# capsh --print  # Shows all capabilities
# chroot /host   # Full host filesystem access!
```

### Secure Docker Run

```bash
# SECURE: Drop all capabilities and add only needed ones
docker run \
  --cap-drop=ALL \
  --cap-add=NET_BIND_SERVICE \
  --security-opt=no-new-privileges:true \
  --read-only \
  my-app:latest
```

### Docker Compose Security Context

```yaml
# SECURE: Docker Compose with security restrictions
version: '3.8'
services:
  app:
    image: my-app:latest
    cap_drop:
      - ALL
    cap_add:
      - NET_BIND_SERVICE  # Only bind to privileged ports
    security_opt:
      - no-new-privileges:true
    read_only: true
    tmpfs:
      - /tmp:size=100M
    user: "1000:1000"  # Non-root user
```

---