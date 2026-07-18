---
source: "common/engineering/threat-modeling.md"
title: "Threat Modeling"
heading: "7. Practical Exercise: Threat Modeling a Web App"
category: "common-vuln"
language: "common"
severity: "medium"
tags: [common-vuln, linddun, pasta, stride, table, what]
chunk: 9/13
---

## 7. Practical Exercise: Threat Modeling a Web App

Let's walk through threat modeling a simple note-taking web application: **NoteVault**.

### Step 1: System Description

- Users register, log in, and create encrypted notes
- Notes stored in PostgreSQL; encryption keys managed by a separate Key Management Service (KMS)
- Frontend: React SPA
- Backend: REST API (Go), JWT-based authentication
- Infrastructure: AWS ECS, RDS PostgreSQL, DynamoDB for sessions
- Third-party: SendGrid for email verification

### Step 2: Draw the DFD

```
[User Browser] ──HTTPS──→ [ALB] ──HTTPS──→ [API Server] ──SQL──→ [(PostgreSQL)]
                      ↑                         │                      │
                      │                         ├──HTTPS──→ [KMS API]  │
                      │                         │                      │
                      │                         └──SMTP──→ [SendGrid]  │
                      │                                              │
                  [DynamoDB Sessions]                            [S3 Backups]
```

Trust boundaries:
- Browser ↔ ALB (Internet → VPC)
- ALB ↔ API Server (VPC internal)
- API Server ↔ PostgreSQL (app → data tier)
- API Server ↔ KMS API (internal → AWS KMS endpoint)
- API Server ↔ SendGrid (VPC → external SaaS)

### Step 3: STRIDE Threats Per Element

#### API Server (Process)

| ID | STRIDE | Threat | Mitigation | Sev |
|---|---|---|---|---|
| T1 | Spoofing | Attacker forges a JWT with stolen signing key | Rotate signing keys, use short-lived tokens, public key pinning | High |
| T2 | Tampering | SQL injection in note content | Parameterized queries, ORM, WAF rule | High |
| T3 | Repudiation | User deletes a note, claims they didn't | Immutable audit log for all note mutations | Medium |
| T4 | Info Disclosure | Error response leaks stack trace with DB hostname | Structured error responses, no stack traces in production | Medium |
| T5 | DoS | Unauthenticated /register endpoint exhaustion | Rate limiting per IP, CAPTCHA, account lockout | Medium |
| T6 | Elevation | User modifies note_id parameter to read another user's note | Ownership check on every read operation: `WHERE user_id = ? AND note_id = ?` | High |

#### PostgreSQL (Data Store)

| ID | STRIDE | Threat | Mitigation | Sev |
|---|---|---|---|---|
| T7 | Tampering | Rogue admin modifies notes directly in DB | Encryption at rest, audit logging, restricted DB access | Medium |
| T8 | Info Disclosure | Backup leaked from S3 contains plaintext notes | Encrypt backups with KMS, restrict S3 bucket policies | High |
| T9 | DoS | Connection pool exhaustion | Connection pooling with max limits, query timeout | Low |

#### Data Flow: API Server → SendGrid

| ID | STRIDE | Threat | Mitigation | Sev |
|---|---|---|---|---|
| T10 | Info Disclosure | API key for SendGrid leaked in logs | Secret scanning in CI, key rotation, log redaction | Medium |
| T11 | Tampering | Man-in-the-middle modifies email verification link | TLS for SMTP (SMTPS or STARTTLS enforced) | Medium |

### Step 4: Prioritize & Assign

**High-severity threats (must-fix before launch):** T1, T2, T6, T8
**Medium-severity (fix within 30 days):** T3, T4, T5, T10, T11
**Low-severity (accept/track):** T9

### Step 5: Create Test Cases

- T2 → SQL injection fuzz tests on all endpoints accepting user input
- T6 → Automated permission tests: user A cannot read/update/delete user B's notes
- T4 → Error handling integration tests: verify no stack traces in production error responses

---