---
source: "common/engineering/security-architecture-patterns.md"
title: "Security Architecture Patterns"
heading: "3. Encryption Strategies"
category: "common-vuln"
language: "common"
severity: "medium"
tags: [access, common-vuln, encryption, identity, logging, monitoring, network, security, segmentation, strategies]
chunk: 4/7
---

## 3. Encryption Strategies

### 3.1 Encryption in Transit

**TLS everywhere — no exceptions.**
- All external endpoints terminate TLS at the edge (LB/CDN).
- Internal service-to-service traffic should also use TLS or mTLS. Even in a private network, encryption prevents sniffing by compromised adjacent services.
- HSTS (`Strict-Transport-Security`) header should be set with a `max-age` of at least one year (31536000) and `includeSubDomains`.
- **TLS versions:** Disable TLS 1.0/1.1. Use TLS 1.2 minimum; prefer TLS 1.3 (reduced handshake latency, better cipher suites).
- **Cipher suites:** Prefer AEAD ciphers (AES-GCM, ChaCha20-Poly1305). Disable CBC-mode ciphers and export-grade suites.

**mTLS for internal traffic:**
Within a service mesh, mTLS is automatic. Outside a mesh, implement mTLS at the application level or through a sidecar proxy. **Never** skip TLS for "internal-only" services — internal networks are not trusted perimeters anymore.

### 3.2 Encryption at Rest

| Level | What's Encrypted | Key Management |
|---|---|---|
| **Storage-level** | Entire disk/volume (LUKS, EBS encryption) | Cloud KMS / platform key |
| **Database-level (TDE)** | Database files, backups | SQL Server TDE, Oracle TDE |
| **Application-level** | Specific fields (PII, secrets in DB) | Application-managed keys |
| **Client-side** | Data before it leaves the client | Client-held keys (zero-knowledge) |

**Envelope encryption (recommended):**
```
Master Key (in KMS/HSM)
    ↓ (encrypts)
Data Key (unique per object)
    ↓ (encrypts)
Plaintext data
```
- The master key never leaves the KMS/HSM.
- Data keys are generated and cached for performance but encrypted by the master key at rest.
- If a data key is compromised, only one object is exposed; rotation of the master key re-wraps all data keys.

**Client-side vs. server-side encryption:**
- **Server-side:** The cloud provider or application encrypts data before storing it. Simpler, but the encryption key is accessible to the service.
- **Client-side:** The client encrypts data before sending it. The service never has the plaintext key. Required for zero-knowledge architectures (end-to-end encrypted SaaS products).
- **Hybrid:** Sensitive fields (PII, credentials) get client-side encryption; the rest is server-side. Common in healthcare and fintech.

### 3.3 Key Management Hierarchy

```
Root of Trust (HSM / Secure Enclave)
    └── Key Encryption Keys (KEKs) — stored in KMS
            └── Data Encryption Keys (DEKs) — unique per data object
                    └── Plaintext data
```

**Key rotation:**
- **Master keys (KEKs):** Rotate annually (or after any security incident). Rotation is a re-wrap operation — existing DEKs get re-encrypted with the new KEK.
- **Data keys (DEKs):** Rotate on a schedule (e.g., every 90 days) or on-demand for sensitive objects. Requires re-encryption of the underlying data.

**Key destruction:**
- Cryptographic destruction (zeroization) is immediate — delete the key from KMS and the data is unrecoverable.
- For compliance (Crypto-shredding): if you delete the KEK, all data encrypted under it becomes permanently inaccessible. This is a feature for data deletion compliance (GDPR right to erasure).

---