---
source: "common/engineering/secrets-management.md"
title: "Secrets Management Engineering Guide"
heading: "4. Secret Rotation"
category: "common-vuln"
language: "common"
severity: "medium"
tags: [anti-patterns, common, common-vuln, counts, encryption, management, rotation, secret, secrets, what]
chunk: 5/8
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