---
source: "common/engineering/secrets-management.md"
title: "Secrets Management Engineering Guide"
heading: "5. Encryption Key Lifecycle"
category: "common-vuln"
language: "common"
severity: "medium"
tags: [anti-patterns, common, common-vuln, counts, encryption, management, rotation, secret, secrets, what]
chunk: 6/8
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