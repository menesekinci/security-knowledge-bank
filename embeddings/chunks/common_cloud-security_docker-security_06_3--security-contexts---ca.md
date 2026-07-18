---
source: "common/cloud-security/docker-security.md"
title: "Docker Security"
heading: "3. Security Contexts & Capabilities"
category: "cloud-security"
language: "common"
severity: "medium"
tags: [cloud-security, containers, contexts, host, mounts, overview, privileged, security, table]
chunk: 6/11
---

## 3. Security Contexts & Capabilities

Linux capabilities granularly control what a process can do. Attackers exploit overprivileged containers.

### Capability Escalation Examples

```bash
# List container capabilities
docker run --rm alpine capsh --print

# Dangerous capabilities:
# CAP_SYS_ADMIN    — Mount filesystems, namespace operations
# CAP_NET_ADMIN    — Interface configuration, firewall manipulation
# CAP_SYS_RAWIO    — I/O port access, dangerous
# CAP_DAC_OVERRIDE — Bypass file permission checks
# CAP_SETUID       — Change user identity
```

### Secure Dockerfile with Capability Reduction

```dockerfile
# SECURE: Dockerfile with non-root user
FROM python:3.11-slim

RUN addgroup --system --gid 1001 appgroup && \
    adduser --system --uid 1001 --gid 1001 appuser

WORKDIR /app
COPY --chown=appuser:appgroup . .

# Drop all setuid/setgid bits from installed files
RUN find / -perm /6000 -type f -exec chmod a-s {} \; 2>/dev/null || true

USER appuser
EXPOSE 8080
CMD ["python", "app.py"]
```

### Runtime Security Check

```bash
# Check current capabilities of a running container
docker inspect --format '{{.HostConfig.CapAdd}}' container-name

# Recommended: Drop all capabilities by default
docker run --cap-drop=ALL --cap-add=CHOWN nginx
```

---