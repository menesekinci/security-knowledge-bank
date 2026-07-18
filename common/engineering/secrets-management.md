# Secrets Management Engineering Guide

> An engineering-focused reference on secrets management — what counts as a secret, common anti-patterns, solutions for different environments, rotation strategies, encryption key lifecycle, and detection workflows.

---

## 1. What Counts as a Secret

A secret is any credential or cryptographic material that, if disclosed, could be used to authenticate or authorize access to a system, data, or resource. The most common categories:

| Category | Examples | Impact if Leaked |
|---|---|---|
| **API keys** | Cloud provider keys (AWS AK/SK), SaaS API tokens | Direct resource access, data exfiltration |
| **Passwords** | Database passwords, admin credentials, application passwords | Authentication bypass, lateral movement |
| **Tokens** | OAuth access tokens, JWT signing keys, session secrets | Session hijacking, token forgery |
| **Certificates** | TLS private keys, mTLS client certificates | MITM, impersonation of trusted services |
| **Encryption keys** | Data encryption keys, key encryption keys, PGP keys | Decryption of sensitive data at rest |
| **Connection strings** | Database URLs with embedded credentials, Redis URLs | Direct data access from any network path |
| **SSH keys** | Private keys for server access, deploy keys | Infrastructure compromise |
| **Environment-specific values** | HMAC secrets, hashing salts, signing secrets | Integrity bypass, hash cracking |
| **Third-party secrets** | Vendor API tokens, SIEM tokens, monitoring credentials | Pivot point into other systems |

**The golden rule:** If it's a string that gates access to anything, it's a secret. Treat it as such from the moment it's generated until the moment it's destroyed.

### What's NOT a Secret (But Often Mistaken for One)

- Public API keys (client-side SDK keys that are designed to be embedded in mobile apps) — these still need rate limiting, but exposure is not catastrophic.
- JWTs that are signed and expire in 5 minutes (but the *signing key* is a secret).
- CSRF tokens (they're one-time and session-bound — stored in app state, not as credentials).

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

## 4. Secret Rotation

### 4.1 Automatic vs. Manual Rotation

| Rotation Type | How It Works | Best For |
|---|---|---|
| **Automatic (integrated)** | The secrets manager rotates the secret and optionally updates the service (e.g., AWS RDS password rotation) | Database passwords, cloud IAM keys |
| **Automatic (custom)** | A scheduled job reads a new secret, updates the target service, then confirms the old version is deactivated | API keys, service account tokens |
| **Manual** | Human generates a new secret, updates all consumers, deactivates the old one | One-off secrets, legacy systems, highly sensitive keys with strict dual control |

**Industry rotation cadences:**

| Secret Type | Recommended Max Lifetime | Rationale |
|---|---|---|
| Database passwords | 90 days | Limits exposure window if credentials are exfiltrated |
| Cloud API keys (IAM user) | 90 days (or avoid — use instance profiles) | Prevents use of compromised credentials |
| TLS certificates | 90 days (90-day certs are becoming the norm) | Reduces damage from private key compromise; automation-friendly |
| JWT signing keys | 1 year (rotate immediately if compromised) | Keys are server-side; less exposure surface |
| SSH keys | 180 days | Less frequent use, but long window if stolen |
| Third-party API tokens | 90 days | Vendor-dependent, but 90 days is a safe default |

### 4.2 Rotation Strategies for Different Secret Types

**Database passwords (zero-downtime):**
1. App reads password from secrets manager at startup (not at every connection).
2. Generate new password → update the database user → update the secret in the secrets manager.
3. **Rolling restart:** Restart app instances one at a time. Each new instance reads the new password.
4. For short transition: keep the old password valid for a cooldown period (e.g., 5 minutes) so existing connections don't drop.

**API keys (dual-key rotation):**
```
Phase 1: Deploy new key alongside the old one (app reads both)
Phase 2: Remove the old key after all consumers have picked up the new one
         └── Validation window: the old key must still be valid during transition
```

**Certificate rotation (automated):**
```
cert-manager (on K8s) or ACME client requests new cert → 
CA issues new cert → 
cert-manager/applies it → 
service reloads TLS config (hot reload, no restart) → 
old cert expires naturally
```

### 4.3 Zero-Downtime Rotation Patterns

Two reliable patterns:

**Pattern 1: Dual-credential acceptance**
- The service accepts authentication against both the old and new secret during rotation.
- This allows consumers to switch over at their own pace.
- After all consumers are on the new secret, the old one is revoked.

**Pattern 2: Leased/rotated at consumption**
- Dynamic secrets (Vault): each consumer gets a unique, short-lived credential.
- When the lease expires, the consumer requests a new one — automatically rotated without coordinated downtime.
- This is the *least friction* approach but requires Vault integration.

---

## 5. Encryption Key Lifecycle

### 5.1 Key Generation, Storage, Rotation, Revocation, Destruction

| Stage | Best Practice | Pitfalls |
|---|---|---|
| **Generation** | Use a cryptographically secure random number generator (CSPRNG) — `/dev/urandom`, `openssl rand`, KMS `GenerateRandom` | Using `Math.random()` or pseudorandom — predictable |
| **Storage** | KMS or HSM — never on filesystem without encryption | Filesystem at rest, config files, environment variables |
| **Rotation** | Re-encrypt data with new key, or re-wrap DEKs with new KEK | Rotating a key without re-encrypting the data (old data is still readable with the old key) |
| **Revocation** | Delete the key from KMS and invalidate any cached copies | Revoking without confirming no cached copies exist (cached data stays encrypted but unreachable) |
| **Destruction** | Cryptographic erasure (delete the key → data is unreadable) | Destroying a key that's in use → service outage |

### 5.2 HSM vs. Software-Based Key Management

| Dimension | HSM (Hardware Security Module) | Software-Based (KMS, Vault Transit) |
|---|---|---|
| **Security** | Keys never leave the hardware — tamper-resistant, certified (FIPS 140-2 Level 3) | Keys in memory, encrypted at rest — software is only as secure as the host |
| **Performance** | Hardware-accelerated crypto | CPU-bound for crypto ops |
| **Cost** | $$$ — dedicated hardware or cloud HSM (AWS CloudHSM, Azure Dedicated HSM) | $ — cloud KMS ($1/key/month) or open source |
| **Operational overhead** | High — key management, firmware updates, HA clustering | Low — managed service |
| **Throughput** | Limited by hardware (but fast) | Soft limits (API rate limits on cloud KMS) |

**When to use HSM:**
- Regulatory requirements (PCI PIN, FIPS 140-2 Level 3, eIDAS)
- Root of trust / key ceremony (generating the master key that protects everything else)
- High-value key material: CA root keys, payment HSM

**When to use software-based:**
- Day-to-day data encryption (envelope encryption with cloud KMS)
- HSMs for the root keys, software KMS for everything else (layered approach)

### 5.3 BYOK (Bring Your Own Key)

BYOK lets you use your own key material in a cloud provider's KMS:

```
You generate the key material → You import it into AWS KMS / GCP Cloud KMS / Azure Key Vault
The cloud provider stores it in an HSM — they can see the encrypted key but not the plaintext
You manage rotation, revocation, and destruction
```

**What BYOK gives you:**
- **Control:** You hold the key material. You can revoke it at any time, making the data inaccessible to the cloud provider.
- **Compliance:** Many regulations require customer-managed keys (GDPR, FedRAMP, PCI DSS).
- **Portability:** In theory, you can export the key and decrypt data on another provider. In practice, export is often restricted or impractical.

**What BYOK doesn't give you:**
- The provider still processes decryption requests (they have the plaintext key in HSM memory while processing). For true zero-knowledge, you need client-side encryption.
- Export: Many BYOK implementations don't allow re-export of the key once imported.

---

## 6. Secret Detection

### 6.1 Tools

| Tool | Approach | Best For |
|---|---|---|
| **truffleHog** | Scans git history for high-entropy strings (shannon entropy). Finds secrets that regex might miss. | Deep git history scanning, finding secrets that don't match a known pattern |
| **Gitleaks** | Regex + entropy — supports hundreds of built-in rules (AWS keys, GitHub tokens, Slack tokens). | CI/CD integration, blocking PRs with secrets |
| **git-secrets** | Pre-commit hooks + git history scanning. Prevents patterns, not entropy. | Simple, lightweight git-native approach |
| **Secret scanner (GitHub Advanced Security)** | Native GitHub scanning on push and history. Automatically alerts repo admins. | GitHub-hosted repos with GHAS license |
| **Detect Secrets (Yelp)** | Custom rules via regex, entropy, and path/file-type allowlists. | Highly customized scanning pipelines |
| **Trivy** | Vulnerability scanner — also detects hardcoded secrets in filesystem and container images. | Container image scanning, IaC scanning |

### 6.2 Pre-Commit Hooks vs. CI Scanning

| Approach | Timing | Pros | Cons |
|---|---|---|---|
| **Pre-commit hook** | Before the commit is created | Catches secrets before they enter history — **no record to clean up** | Bypassable (`git commit --no-verify`), not enforceable on all developers |
| **Pre-receive hook (server-side)** | After `git push`, before the server accepts | Cannot be bypassed by developers; enforced on all pushes | Must be configured on the git server (GitHub/GitLab/Bitbucket) |
| **CI scan (PR stage)** | After push, on pull request | Catches secrets in PRs; automated blocking; integrates with code review | Secret is already in the remote branch (retracted push still leaves a trace) |
| **Scheduled scan** | Daily/weekly full history scan | Catches secrets that bypassed other checks | Post-facto — secret has been in history for hours or days |

**Recommended stack:**
1. **Pre-commit hook** (truffleHog or Gitleaks with `protect` mode) — stops 90% of accidental commits.
2. **CI scan** (Gitleaks on PRs) — catches the 10% that bypassed pre-commit (`--no-verify`).
3. **Scheduled scan** (truffleHog on full git history weekly) — catches anything missed and monitors for historical leaks.
4. **Alert on push** (GitHub push protection) — real-time alerting for known secret patterns.

### 6.3 Incident Response for Leaked Secrets

If you discover a secret has been leaked:

**Immediate (within 1 hour):**
1. **Rotate the secret** — generate a new one and update all legitimate consumers. Do not wait for investigation.
2. **Revoke the leaked secret** — invalidate it at the source (cloud IAM, vendor portal, database user).
3. **Assess exposure window** — when was the commit made? When was it pushed? Who has access to the repo?

**Investigation (within 24 hours):**
4. **Check access logs** — was the leaked secret used to access any resource between the commit and revocation? Cloud provider logs (CloudTrail, audit logs) show API calls made with that credential.
5. **Check downstream clones** — if the repo is public or has many forks, the secret is compromised widely. Assume the worst.
6. **Determine root cause** — was it a developer mistake, CI misconfiguration, or a targeted attack?

**Remediation (within 1 week):**
7. **Remove the secret from git history** — use `git-filter-repo` or BFG Repo-Cleaner. Note: this rewrites history and impacts all collaborators. Coordinate carefully.
8. **Enforce additional controls** — add pre-commit hooks, enhance CI scanning, restrict repo permissions.
9. **Update incident timeline** — include in postmortem and update the risk register.

**Key principle:** Rotating the secret is non-negotiable. Even if you think no one used it, rotate. Assume the worst — the cost of a false alarm is a single credential rotation; the cost of not rotating is a breach.

---

## 7. References

| Resource | Focus | URL |
|---|---|---|
| **OWASP Secrets Management Cheat Sheet** | Comprehensive guide to secrets management | https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html |
| **HashiCorp Vault Documentation** | Vault architecture, deployment, and API reference | https://developer.hashicorp.com/vault/docs |
| **AWS Secrets Manager Documentation** | AWS-native secrets management | https://docs.aws.amazon.com/secretsmanager/ |
| **Kubernetes Secrets (Official Docs)** | K8s native secrets and encryption at rest | https://kubernetes.io/docs/concepts/configuration/secret/ |
| **GitHub Secret Scanning About** | GitHub push protection and secret scanning | https://docs.github.com/en/code-security/secret-scanning |
| **Gitleaks Documentation** | Git-based secret scanning tool | https://github.com/gitleaks/gitleaks |
| **NIST SP 800-57 (Key Management)** | Cryptographic key management guidelines | https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final |

### Related Docs in This Knowledge Bank

- [Secure CICD](../secure-cicd.md) — CI/CD pipeline security including secret injection patterns
- [Incident Response](../incident-response.md) — Procedures for handling secret leak incidents
- [Agent Security](../agent-security.md) — Secrets management for autonomous agent systems
- [MCP Security](../mcp-security.md) — Secrets handling in the Model Context Protocol
