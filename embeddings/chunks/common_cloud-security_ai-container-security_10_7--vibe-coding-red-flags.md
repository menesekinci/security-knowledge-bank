---
source: "common/cloud-security/ai-container-security.md"
title: "AI-Generated Container & Kubernetes Security"
heading: "7. Vibe-Coding Red Flags"
category: "cloud-security"
language: "common"
severity: "critical"
tags: [cloud-security, code, explanation, overview, table, vulnerability, vulnerable]
chunk: 10/11
---

## 7. Vibe-Coding Red Flags

Watch for these AI-generated patterns in Dockerfiles and Kubernetes manifests. Each is a sign that the AI prioritized functionality over security:

| # | Red Flag | Risk | Fix |
|---|---|---|---|
| 1 | `FROM ...:latest` (no digest) | Base image silently rolls to vulnerable version | Pin with `@sha256:...` |
| 2 | `USER root` or no `USER` instruction | Container runs with host root privileges | Add `USER appuser` with dedicated UID |
| 3 | `ENV` with database URLs or API keys | Secrets baked into immutable image layers | Use runtime secrets injection |
| 4 | `ADD` instead of `COPY` | Auto-extraction of archives (zip-slip, symlink attacks) | Always use `COPY` for application files |
| 5 | `COPY . /app` without `.dockerignore` | Secrets, `.git`, `node_modules` in image | Add `.dockerignore`; copy specific files only |
| 6 | `npm install -g` or `pip install` without hashes | Supply chain risk, global privilege escalation | Use `npm ci`, `--require-hashes`, `--no-cache-dir` |
| 7 | No `securityContext` in K8s pod spec | Root container with default (dangerous) capabilities | Add `runAsNonRoot: true`, `capabilities.drop: ["ALL"]` |
| 8 | `privileged: true` | Full host access for container | Drop privilege; add only required capabilities |
| 9 | `hostNetwork: true` | Container bypasses network isolation | Remove; use service mesh or NetworkPolicy instead |
| 10 | `ClusterRoleBinding` to `cluster-admin` | Full cluster compromise if pod is breached | Use namespace-scoped `Role` with minimal verbs |
| 11 | No `NetworkPolicy` | All pods can reach all pods | Add default-deny + specific allow policies |
| 12 | Secrets as env vars (`valueFrom.secretKeyRef`) | Credentials visible in `/proc` and `kubectl exec` | Mount secrets as files (`readOnly: true`) |
| 13 | `type: NodePort` for internal services | Service exposed on every node's IP | Use `ClusterIP` with ingress controller |
| 14 | No resource limits (`resources.limits`) | Container can exhaust cluster resources | Always set CPU/memory `requests` and `limits` |
| 15 | No probes (liveness/readiness) | Traffic routed to dead/unhealthy containers | Add HTTP probes pointing to `/health` and `/ready` |
| 16 | Container running with all capabilities | Broad syscall access enables escape | `cap_drop: ["ALL"]` — add back only what's needed |
| 17 | No `readOnlyRootFilesystem` | Write access enables malware persistence | Set `readOnlyRootFilesystem: true` with `emptyDir` for temp |

---