---
source: "common/engineering/secrets-management.md"
title: "Secrets Management Engineering Guide"
heading: "3. Secrets Management Solutions"
category: "common-vuln"
language: "common"
severity: "medium"
tags: [anti-patterns, common, common-vuln, counts, encryption, management, rotation, secret, secrets, what]
chunk: 4/8
---

## 3. Secrets Management Solutions

### 3.1 HashiCorp Vault

Vault is the gold standard for secrets management — it handles static secrets, dynamic secrets (generated on demand), encryption as a service, and key rotation.

**Key features:**
- **Dynamic secrets:** Database credentials, cloud IAM keys generated on demand with automatic expiry. The consumer gets a credential that works for 1 hour, then disappears.
- **Secret leasing:** All secrets have a lease duration. When the lease expires, Vault revokes the secret automatically (for dynamic secrets) or requires renewal (for static secrets).
- **Wrapping:** Secrets can be "wrapped" in a single-use token. You share the token, not the secret itself. The recipient unwraps it in Vault, getting the actual secret in a one-time response.
- **Policies:** Fine-grained ACLs on who can read/write which paths. Enforced at the Vault layer, not the application layer.

**Deployment patterns:**

| Pattern | Pros | Cons |
|---|---|---|
| **Self-managed Vault cluster** | Full control, air-gapped capable | Operational overhead (HA, storage backend, unsealing) |
| **Vault on K8s (Helm chart)** | Tight K8s integration via Vault Agent Injector, auto-unseal with KMS | Requires K8s expertise, cluster resources |
| **HCP Vault (HashiCorp Cloud)** | Managed, high-availability, no ops | Vendor dependency, egress costs |

**Vault Agent Injector (K8s):**
The most elegant K8s integration: sidecar proxy injects secrets as volumes or environment variables into pods. The app never calls Vault directly.

```
Pod creation → Vault Agent sidecar authenticates → fetches secrets → writes to shared volume → app reads from file
```

### 3.2 AWS Secrets Manager / Parameter Store

| Feature | Secrets Manager | Parameter Store (Standard) | Parameter Store (Advanced) |
|---|---|---|---|
| **Secret size** | 64 KB | 4 KB | 8 KB |
| **Automatic rotation** | Yes (RDS, Redshift, DocumentDB) | No | No |
| **Cross-account access** | Yes (resource policies) | Yes (with KMS) | Yes (with KMS) |
| **Cost** | $0.40/secret/month + $0.05/10K API calls | Free | $0.05/parameter/month |
| **Key rotation** | Manual + scheduled | N/A | N/A |

**When to use which:**
- **Secrets Manager:** For database credentials, API keys — anything that needs automatic rotation or cross-account sharing.
- **Parameter Store (Standard):** For configuration values that aren't sensitive (feature flags, public endpoints).
- **Parameter Store (Advanced):** For sensitive values where cost is a concern (larger secrets, many parameters).

**Integration with ECS/EKS:**
Both services have native integrations with ECS task definitions and EKS secrets store CSI driver. Secrets are injected as environment variables or mounted as volumes — no application changes needed.

### 3.3 Kubernetes Secrets (with Encryption at Rest)

Kubernetes Secrets are the native mechanism, but they require careful handling:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: app-secret
type: Opaque
data:
  password: c3VwZXJzZWNyZXQ=  # base64
```

**Without encryption at rest:** The secret value is stored as plaintext in etcd. Anyone with etcd access (snapshot, backup, direct read) has all secrets.

**With encryption at rest (KMS):**
```
1. Enable EncryptionConfiguration in the API server
2. Configure a KMS provider (AWS KMS, GCP Cloud KMS, Azure Key Vault, or local)
3. The API server encrypts the secret before writing to etcd
4. On read, the API server decrypts it — clients never see encrypted data
```

**Limitations of native Secrets:**
- No audit trail for who accessed which secret (unless you enable monitoring on etcd/KMS).
- No automatic rotation.
- No dynamic secrets.
- Subject to RBAC misconfiguration (anyone with `get` on a Secret resource can read the base64 value).

**Better alternatives on K8s:**
- **External Secrets Operator:** Syncs secrets from AWS/Azure/GCP/Vault into K8s Secret objects. The source of truth stays in the cloud.
- **Sealed Secrets:** Encrypts secrets in git — only the controller running in the cluster can decrypt them. Enables GitOps for secrets.
- **Vault Agent Injector:** Sidecar-driven, no K8s Secret objects created at all.

### 3.4 GitHub Actions Secrets

GitHub provides per-repository and per-environment encrypted secrets for CI/CD:

| Feature | Repository Secrets | Environment Secrets | Organization Secrets |
|---|---|---|---|
| **Scope** | Single repo | Specific deploy environment (prod, staging) | All repos in org (or selected) |
| **Visibility** | Visible to all workflows in the repo | Visible to workflows targeting that environment | Visible to selected repos |
| **Audit log** | Yes (GitHub audit log) | Yes | Yes |
| **Rotation** | Manual (via UI or API) | Manual | Manual |

**Best practices:**
- Use **environment secrets** for production credentials — this adds a protection gate (required reviewers, wait timer).
- Never use `echo` to print a secret in a workflow — GitHub masks secrets in output, but rule-breaking characters can bypass the mask.
- Use **OIDC (OpenID Connect)** instead of static secrets where possible. GitHub Actions can get short-lived, workload-attested tokens to authenticate to cloud providers without storing any long-lived credentials.
- Rotate CI secrets more frequently than application secrets — CI has wide blast radius (code access, deploy permissions).

---