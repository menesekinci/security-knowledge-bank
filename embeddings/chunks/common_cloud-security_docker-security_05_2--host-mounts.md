---
source: "common/cloud-security/docker-security.md"
title: "Docker Security"
heading: "2. Host Mounts"
category: "cloud-security"
language: "common"
severity: "medium"
tags: [cloud-security, containers, contexts, host, mounts, overview, privileged, security, table]
chunk: 5/11
---

## 2. Host Mounts

Mounting host directories into containers exposes the host filesystem. The most dangerous mounts:

| Mount | Risk |
|---|---|
| `/:/host` | Full host filesystem access |
| `/var/run/docker.sock:/var/run/docker.sock` | Docker socket — escape via `docker exec` |
| `/proc:/proc` | Kernel parameter manipulation |
| `/dev:/dev` | Device node manipulation |

### Vulnerable Docker Compose (Docker Socket Mount)

```yaml
# VULNERABLE: Docker socket mounted into container
version: '3.8'
services:
  jenkins:
    image: jenkins/jenkins:lts
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock  # Container escape vector!
      - /:/host  # Full host filesystem
```

### Secure Alternative (Docker-in-Docker with Restriction)

```yaml
# SECURE: Use Docker-outside-of-Docker with TLS, or avoid socket mount entirely
version: '3.8'
services:
  ci-worker:
    image: my-ci-worker:latest
    volumes:
      # Only mount specific directories, read-only
      - ./workspace:/workspace:ro
    # No Docker socket mount — use remote Docker API with TLS
    environment:
      DOCKER_HOST: tcp://docker-host:2376
      DOCKER_TLS_VERIFY: "1"
      DOCKER_CERT_PATH: /certs
```

### Secure Mount Patterns

```dockerfile
# Dockerfile: Use COPY instead of mounting volumes for production
FROM node:18-alpine
WORKDIR /app
COPY package*.json ./
COPY src/ ./src/
RUN npm ci --only=production
USER node  # Drop to non-root
CMD ["node", "app.js"]
```

---