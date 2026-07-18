# Docker Security

> **Category:** Common / Cloud Security
> **Last Updated:** July 2026

## Overview

Docker containers share the host kernel, making container isolation critical. This document covers privileged containers, host mounts, security contexts, image scanning, rootless mode, and container escape vulnerabilities with CVE-backed examples.

---

## Table of Contents

1. [Privileged Containers](#1-privileged-containers)
2. [Host Mounts](#2-host-mounts)
3. [Security Contexts & Capabilities](#3-security-contexts--capabilities)
4. [Image Scanning & Supply Chain](#4-image-scanning--supply-chain)
5. [Rootless Mode](#5-rootless-mode)
6. [CVEs & Real-World Examples](#6-cves--real-world-examples)

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

## 4. Image Scanning & Supply Chain

Container images can contain vulnerable dependencies, malicious layers, or embedded secrets.

### Vulnerable Pattern (No Image Scanning)

```dockerfile
# VULNERABLE: Using untrusted base image with known vulnerabilities
FROM node:14  # EOL, unpatched CVEs
COPY . /app
RUN npm install  # No audit, pulls vulnerable packages
```

### Secure Image Scanning Workflow

```yaml
# SECURE: GitHub Actions with image scanning
name: Build and Scan

on:
  push:
    branches: [main]

jobs:
  build-and-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Build image
        run: docker build -t my-app:${{ github.sha }} .
      
      - name: Scan image for vulnerabilities
        uses: aquasecurity/trivy-action@master
        with:
          image-ref: my-app:${{ github.sha }}
          severity: 'CRITICAL,HIGH'
          exit-code: '1'
      
      - name: Sign and push
        if: success()
        run: |
          docker tag my-app:${{ github.sha }} my-registry/my-app:latest
          docker push my-registry/my-app:latest
```

```dockerfile
# SECURE: Minimal, multi-stage build with small base image
FROM node:18-alpine AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production && npm audit --audit-level=high

FROM node:18-alpine
WORKDIR /app
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/dist ./dist
RUN addgroup -S app && adduser -S app && \
    chown -R app:app /app
USER app
CMD ["node", "server.js"]
```

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

## 6. CVEs & Real-World Examples

### CVE-2025-23266 — NVIDIA Container Toolkit Escape (NVIDIAScape)
- **Description**: Critical container escape vulnerability (CVSS 9.0) in NVIDIA Container Toolkit. Attackers with GPU access could escape the container and get code execution on the host. This was a systemic risk to AI infrastructure running GPU-accelerated containers
- **Affected**: NVIDIA Container Toolkit <= 1.17.7 (and GPU Operator <= 25.3.0)
- **CVSS**: 9.0 (Critical) — CVSS:3.1/AV:A/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H (CWE-426)
- **Fix**: Upgrade NVIDIA Container Toolkit to >= 1.17.8
- **Source**: https://www.wiz.io/blog/nvidia-ai-vulnerability-cve-2025-23266-nvidiascape

### CVE-2025-9074 — Docker Desktop Container Escape
- **Description**: Vulnerability in Docker Desktop (<= 4.44.3) allowing a local Linux container to reach the Docker Engine API over the configured Docker subnet (`192.168.65.7:2375` by default, with or without Enhanced Container Isolation), enabling container escape on Windows and macOS
- **Affected**: Docker Desktop < 4.44.3 on Windows and macOS
- **CVSS**: 9.3 (Critical) — CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H (CWE-668)
- **Fix**: Upgrade to Docker Desktop >= 4.44.3
- **PoC**: https://github.com/PtechAmanja/CVE-2025-9074-Docker-Desktop-Container-Escape
- **Source**: https://nvd.nist.gov/vuln/detail/cve-2025-9074

### runc Container Escape (November 2025 — Multiple CVEs)
- **Description**: Three high-severity vulnerabilities disclosed in runc (the container runtime used by Docker). The most critical involved "masked path" abuse — attackers could write to host filesystem paths that should have been hidden by the runtime. This allowed full container breakouts
- **Affected**: runc <= 1.1.x
- **CVSS**: 8.6 (High)
- **Fix**: Upgrade to runc >= 1.2.0
- **Source**: https://www.sysdig.com/blog/runc-container-escape-vulnerabilities/

### "Leaky Vessels" Vulnerabilities (2024)
- **Description**: Multiple container escape vulnerabilities discovered by Palo Alto Networks affecting Docker and runc. Flaws allowed attackers to escape containers through filesystem operations and runtime misconfigurations
- **Affected**: Docker Engine, runc
- **CVSS**: 8.6 (High)
- **Fix**: Update to latest Docker Engine and runc versions
- **Source**: https://www.paloaltonetworks.com/blog/cloud-security/leaky-vessels-vulnerabilities-container-escape/

### CVE-2025-23266 (Continued) — AI/ML Infrastructure Risk
- **Description**: Beyond the container escape, this vulnerability specifically threatens AI infrastructure where GPU-sharing is common. Attackers with container access could read GPU memory from other tenants
- **Remediation**:
  - Scan all container images for vulnerable NVIDIA Container Toolkit versions
  - Use pod security standards that restrict `hostPID` and `hostNetwork`
  - Consider hypervisor-based isolation for multi-tenant GPU workloads
- **Source**: https://www.upwind.io/feed/understanding-the-nvidiascape-cve-2025-23266-container-toolkit-vulnerability

### Docker Image Supply Chain (2022-ongoing)
- **Description**: Thousands of malicious images on Docker Hub exfiltrate credentials, mine cryptocurrency, and deploy backdoors. Official images (e.g., official Docker Hub images) are safer but still may contain vulnerable packages
- **Fix**: Use only trusted base images; pin image digests; scan with Trivy/Snyk; enforce image signing with Docker Content Trust
- **Source**: https://docs.docker.com/security/security-announcements/

---

## 7. AI-Generated Dockerfile Risks

### The Challenge

AI coding assistants (GitHub Copilot, Cursor, Claude Code, ChatGPT) are now the primary way many developers create Dockerfiles. Research by OX Security (2026) found that **62% of AI-generated code ships with vulnerabilities**, and Dockerfiles are among the highest-risk categories because AI models default to patterns that prioritize "works everywhere" over "works securely." A typical AI-generated Dockerfile will use `FROM ubuntu:latest`, run as root, bake secrets into `ENV` variables, use `ADD` instead of `COPY`, and skip HEALTHCHECK — every one of these is a security issue.

The Cloud Security Alliance documented a **400% increase in cloud misconfiguration vulnerabilities** traced to AI-generated code from 2024 to 2026, with 45% of AI-generated cloud configuration samples introducing OWASP Top 10 vulnerabilities. Dockerfiles generated by AI inherit insecure defaults from the training corpus — public GitHub repositories where quick-start examples rarely follow security best practices.

### Common AI-Generated Dockerfile Vulnerabilities

| AI Default | Security Impact | Secure Alternative |
|---|---|---|
| `FROM ubuntu:latest` | Unpinned base image silently rolls to vulnerable versions | Pin to digest: `FROM node:20-alpine@sha256:abc...` |
| `USER root` (implicit or explicit) | Container runs with host root privileges | Add `adduser` + `USER appuser` |
| `ENV DATABASE_URL=postgres://admin:pass@host/db` | Secrets baked into immutable image layers, visible via `docker history` | Use Docker secrets or K8s External Secrets at runtime |
| `ADD https://example.com/archive.tar.gz /tmp/` | Auto-extracts archives; potential zip-slip or symlink attacks | Use `COPY` for local files, `curl` for remote |
| `COPY . /app` without `.dockerignore` | Secrets, `.git`, credentials copied into image | Add `.dockerignore`; copy specific files with `COPY --chown` |
| `RUN pip install` or `npm install` without hashes | Supply chain risk — no integrity verification | `pip install --require-hashes` or `npm ci` + audit |
| `EXPOSE 80 443 3000 5432` | Over-exposed ports increase attack surface | Only expose the minimum port your app serves on |
| No `HEALTHCHECK` | Container fails silently; orchestration doesn't restart it | Add `HEALTHCHECK CMD` with HTTP endpoint |
| `CMD bash` or `CMD npm start` | No process supervision; easy to overwrite entrypoint | Use the application binary directly, not a wrapper script |

### Mitigation Strategy

Every AI-generated Dockerfile must pass through a security review before use. Specific controls:

1. **Run automated scanning** on every AI-generated Dockerfile: `docker scout quick` (Docker Scout), Trivy, or Checkov for IaC scanning
2. **Use the Dockerfile linter**: `hadolint` catches many AI-generated bad patterns (`latest` tag, missing USER, `apt-get` without `--no-install-recommends`)
3. **Enforce policies with build-time checks**: Use Docker BuildKit's `--check` flag or OPA/conftest to reject builds that use `:latest`, run as root, or contain `ENV` with credential patterns
4. **Mandatory code review**: No AI-generated Dockerfile should go to production without a human review by someone who understands container security
5. **Use hardened base images**: Prefer `chainguard` (distroless), `gcr.io/distroless`, or `scratch` over general-purpose OS images
6. **Run the builder with --cap-drop**: Even at build time, restrict capabilities: `docker build --security-opt=no-new-privileges:true`

### The Moltbook Precedent

The January 2026 Moltbook breach was the first high-profile incident where a founder publicly admitted the entire application was "vibe-coded" (built by AI without writing code). Wiz Research discovered a misconfigured Supabase database exposing **1.5 million API tokens** and 35,000 email addresses within minutes. The vulnerability — an API key exposed in client-side JavaScript with no Row Level Security on the database — was exactly the kind of configuration gap an experienced engineer would catch in review. The incident demonstrated that AI-generated infrastructure code, including any Dockerfiles and deployment configurations in the pipeline, needs the same security review as manually-written code, if not more.

For a comprehensive deep-dive into AI-generated container and K8s security mistakes, including verified CVEs, vibe-coding red flags, and a prevention checklist, see [ai-container-security.md](./ai-container-security.md).

---

## References

- [Docker Security — Official Documentation](https://docs.docker.com/engine/security/)
- [Docker Security Announcements](https://docs.docker.com/security/security-announcements/)
- [Docker Building Best Practices](https://docs.docker.com/build/building/best-practices/)
- [Aikido — 9 Common Docker Container Security Vulnerabilities](https://www.aikido.dev/blog/docker-container-security-vulnerabilities)
- [Wiz — NVIDIAScape (CVE-2025-23266)](https://www.wiz.io/blog/nvidia-ai-vulnerability-cve-2025-23266-nvidiascape)
- [Sysdig — runc Container Escape Vulnerabilities](https://www.sysdig.com/blog/runc-container-escape-vulnerabilities)
- [Orca Security — New runC Vulnerabilities](https://orca.security/resources/blog/new-runc-vulnerabilities-allow-container-escape/)
- [Palo Alto Networks — Leaky Vessels](https://www.paloaltonetworks.com/blog/cloud-security/leaky-vessels-vulnerabilities-container-escape/)
- [OX Security — Vibe Coding Security: 62% of AI-Generated Code Ships With Vulnerabilities](https://www.ox.security/blog/vibe-coding-security/)
- [Cloud Security Alliance — AI-Generated Code Vulnerability Surge](https://labs.cloudsecurityalliance.org/research/csa-research-note-ai-generated-code-vulnerability-surge-2026/)
- [Wiz — Moltbook Database Exposure](https://www.wiz.io/blog/exposed-moltbook-database-reveals-millions-of-api-keys)
- [Northflank — How to Vibe Code Securely](https://northflank.com/blog/how-to-vibe-code-securely)
- [Flare — Docker Hub Secrets Exposed](https://flare.io/learn/resources/docker-hub-secrets-exposed)
