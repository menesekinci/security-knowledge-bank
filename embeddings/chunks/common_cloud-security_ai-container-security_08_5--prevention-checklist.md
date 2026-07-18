---
source: "common/cloud-security/ai-container-security.md"
title: "AI-Generated Container & Kubernetes Security"
heading: "5. Prevention Checklist"
category: "cloud-security"
language: "common"
severity: "critical"
tags: [cloud-security, code, explanation, overview, table, vulnerability, vulnerable]
chunk: 8/11
---

## 5. Prevention Checklist

- [ ] **Pin base images to SHA256 digests** — never use `:latest` or floating tags. Use `FROM node:20-alpine@sha256:abc...`
- [ ] **Use multi-stage builds** — separate build-time tooling from runtime artifacts
- [ ] **Run as non-root user** — always add `USER` instruction with a dedicated user; never default to root
- [ ] **Drop all Linux capabilities at runtime** — `--cap-drop=ALL --cap-add=NEEDED_ONLY`
- [ ] **Add HEALTHCHECK** — configure both `HEALTHCHECK` (Dockerfile) and probes (K8s manifest)
- [ ] **Never bake secrets into images** — use runtime secrets injection (Docker secrets, K8s External Secrets Operator, vault)
- [ ] **Use Pod Security Standards (`restricted` profile)** — enforce via namespace labels
- [ ] **Add NetworkPolicies** — default-deny with specific allow rules; never rely on the default allow-all
- [ ] **Set resource limits** — CPU and memory bounds prevent DoS; set both `requests` and `limits`
- [ ] **Use readOnlyRootFilesystem** — prevents write-based container escape techniques
- [ ] **Set seccomp profile to RuntimeDefault** — restricts available syscalls
- [ ] **Review ALL AI-generated Dockerfile instructions** — especially `ADD`, `ENV`, `RUN`, `USER`, and `EXPOSE`
- [ ] **Run `docker scout` or Trivy on every build** — catch vulnerabilities before deployment
- [ ] **Use `.dockerignore`** — prevent secrets and build artifacts from being copied into images
- [ ] **Audit AI-generated RBAC** — never use `cluster-admin`; scope roles to namespaces
- [ ] **Set `allowPrivilegeEscalation: false`** — prevents privilege escalation within the container
- [ ] **Verify image signatures** — use Docker Content Trust or cosign for supply chain integrity

---