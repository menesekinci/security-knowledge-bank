---
source: "common/engineering/secrets-management.md"
title: "Secrets Management Engineering Guide"
heading: "2. Common Anti-Patterns"
category: "common-vuln"
language: "common"
severity: "medium"
tags: [anti-patterns, common, common-vuln, counts, encryption, management, rotation, secret, secrets, what]
chunk: 3/8
---

## 2. Common Anti-Patterns

### 2.1 .env Files in Git History

The most pervasive anti-pattern. Developers add `.env` to `.gitignore`, but someone inevitably commits it once — and that commit lives in the git history forever.

**Why it's dangerous:**
- Git history is replicated to every clone, branch, fork, and backup.
- Even if you delete the file, the commit stays in the history. Tools like `git-filter-repo` can scrub it, but only if applied before anyone else clones.
- Automated secret scanners (truffleHog, Gitleaks) routinely find credentials in old commits years after the fact.

**Mitigations:**
- Use `.env.example` files with placeholder values (never real secrets).
- Add a pre-commit hook that blocks `.env` files (see section 6.2).
- Regularly scan git history with secret detection tools.
- If a secret was committed, rotate it immediately — git cleanup is a best-effort supplement, not a fix.

### 2.2 Hardcoded in Source Code

```python
# ❌ DO NOT DO THIS
DB_PASSWORD = "SuperSecret123!"
```

Or worse, in the application binary:

```c
// Hardcoded in compiled code — extractable with strings
const char *api_key = "sk-xxxxxx";
```

**Why it's dangerous:**
- Source code ends up in CI logs, IDE caches, test artifacts, error reports, stack traces.
- Compiled binaries can be reverse-engineered (`strings`, `objdump`, Ghidra).
- Anyone with read access to the repo has the secret.

**Mitigations:**
- Use environment variables or configuration injectors at deploy time.
- Never commit real secrets to any repository (public or private).
- Use secrets management tools (Vault, Secrets Manager) for runtime retrieval.

### 2.3 ConfigMaps Without Encryption (Kubernetes)

```yaml
# ❌ DO NOT DO THIS
apiVersion: v1
kind: ConfigMap
metadata:
  name: app-config
data:
  DB_PASSWORD: c3VwZXJzZWNyZXQ=  # base64 is NOT encryption
```

Base64 encoding is encoding, not encryption. Anyone with `kubectl get configmap` access can decode it instantly.

**Mitigations:**
- Use Kubernetes Secrets (which are base64-encoded by default too, but support encryption at rest via KMS).
- Use an external secrets operator (External Secrets Operator, Sealed Secrets, Vault Agent Injector) — these fetch secrets at runtime and never store them statically in K8s objects.
- Enable encryption at rest for etcd (KMS provider — AWS KMS, GCP Cloud KMS, Azure Key Vault).

### 2.4 Shared Secrets Between Services

When two services share the same API key or password, you lose auditability and increase blast radius:

- **No non-repudiation:** You can't tell which service made a call.
- **Cascading compromise:** One service's breach exposes every service that shares the secret.
- **Rotation nightmares:** Rotating a shared secret requires coordinated downtime of all consuming services.

**Mitigations:**
- Every service gets its own identity (SPIFFE, mTLS certificate, or a unique API key generated for that workload).
- Use OAuth2 client credentials with per-service scopes.
- If sharing is architecturally unavoidable (legacy systems), isolate the shared secret behind a dedicated proxy service that can log and rate-limit usage.

---