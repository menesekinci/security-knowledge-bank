---
source: "common/engineering/zero-trust-architecture.md"
title: "Zero Trust Architecture"
heading: "3. The Five Pillars of Zero Trust"
category: "common-vuln"
language: "common"
severity: "medium"
tags: [beyondcorp, common-vuln, core, five, google, principles, table, what, zero]
chunk: 5/10
---

## 3. The Five Pillars of Zero Trust

CISA and NIST SP 800-207 define Zero Trust across five complementary pillars. Each pillar addresses a different facet of the architecture.

```
┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐
│ Identity │ │  Device  │ │ Network  │ │Application│ │   Data   │
├──────────┤ ├──────────┤ ├──────────┤ ├──────────┤ ├──────────┤
│ • Who    │ │ • What   │ │ • How    │ │ • What   │ │ • What   │
│ • Strong │ │ • Posture│ │ • Micro- │ │ • Perms  │ │ • Classi-│
│   Auth   │ │   Check  │ │   seg    │ │ • Secure │ │   fication│
│ • Contin-│ │ • Cert   │ │ • East-  │ │   SDLC   │ │ • Encryp-│
│   uous   │ │   Mgmt   │ │   West   │ │ • API    │ │   tion   │
│ • Risk-  │ │ • Compli-│ │ • Encryp-│ │   Secu-  │ │ • DLP   │
│   based  │ │   ance   │ │   tion   │ │   rity   │ │          │
└──────────┘ └──────────┘ └──────────┘ └──────────┘ └──────────┘
                       │
                ┌──────┴──────┐
                │   Policy    │
                │  Engine +   │
                │   Enforcer  │
                └─────────────┘
```

### 3.1 Identity

Identity is the new perimeter. In Zero Trust, who you are matters more than where you are.

| Control | Implementation | Why It Matters |
|---|---|---|
| Strong authentication | MFA/WebAuthn/passkeys for all users | Passwords alone are compromised daily; phish-resistant auth eliminates entire attack classes |
| Continuous verification | Re-verify identity on high-risk actions (large transfer, privilege change, new device) | Session tokens can be stolen; re-verification limits token theft damage |
| Identity federation | SAML/OIDC with centralized IdP (Okta, Azure AD, Keycloak) | One source of truth for identity; consistent policy across all applications |
| Service identities | SPIFFE/SPIRE for workload identity, mTLS for service-to-service | Microservices need identities too; VPN or IP-based trust is insufficient |
| Conditional access | Risk-based policies (location, device, behavior) | Same user may get different access from a managed laptop vs a personal phone |

### 3.2 Device

Every device that accesses corporate resources must be verified for health and compliance before access is granted.

| Control | Implementation | Why It Matters |
|---|---|---|
| Device enrollment | MDM (Jamf, Intune, Workspace One) or device attestation | An unmanaged device cannot be trusted to enforce security policy |
| Posture assessment | Check OS version, patch level, encryption, disk encryption, malware status | A compromised device should not access sensitive resources |
| Certificate management | Device certificates via internal CA or cloud PKI | Certificates are stronger than passwords and support mTLS |
| Compliance enforcement | Block or quarantine non-compliant devices; provide remediation guidance | Don't let an unpatched Windows 7 connect to production |

**Pragmatic note for startups:** If you don't have an MDM yet, at minimum require:
- Disk encryption (FileVault/BitLocker) on company devices
- Managed browser (Chrome with policy) for accessing internal apps
- Hardware-bound credentials (YubiKey, TPM-backed keys) for admin access

### 3.3 Network

The network is no longer the security boundary — it is treated as a hostile environment, even inside the data center.

| Control | Implementation | Why It Matters |
|---|---|---|
| Micro-segmentation | Kubernetes NetworkPolicies, AWS Security Groups per service, service mesh | Limit lateral movement; a compromised web server cannot reach the database directly |
| East-west encryption | mTLS via service mesh (Istio, Linkerd, Consul) or application-level encryption | Traffic inside the cluster is not implicitly trusted |
| Identity-aware proxy | BeyondCorp-style access proxy (Google IAP, Cloudflare Access, Pomerium, Tailscale) | Access based on identity + device, not IP |
| Network flow logs | VPC Flow Logs, K8s network audit | Detect anomalous lateral movement patterns |
| No inbound firewall holes | No SSH/RDP open to the internet; use bastion with session recording | Direct inbound connectivity is antithetical to Zero Trust |

### 3.4 Application

Applications and workloads enforce their own access controls rather than relying on the network.

| Control | Implementation | Why It Matters |
|---|---|---|
| Application-level authZ | OAuth 2.0 / OIDC, not network ACLs | Authorization happens inside the app, not at the firewall |
| Secure SDLC | Threat modeling, SAST, dependency scanning, SBOM | Applications must be secure by default, not reliant on perimeter defenses |
| API security | API gateways with auth, rate limiting, schema validation | APIs are the primary attack surface in modern architectures |
| Runtime protection | WAF, RASP, runtime security monitoring | Detect and block attacks as they happen |
| Least-privilege permissions | App-specific service accounts, scoped API keys | If an application is compromised, its blast radius is limited |

### 3.5 Data

Data is the ultimate asset — all other pillars exist to protect it. Data-centric security means protecting data regardless of location or transport.

| Control | Implementation | Why It Matters |
|---|---|---|
| Data classification | Labels: Public, Internal, Confidential, Restricted (or similar tiers) | You cannot protect what you do not classify |
| Encryption at rest | AES-256 encryption for databases, S3 buckets, EBS volumes | Physical access to storage does not mean access to data |
| Encryption in transit | TLS 1.2+ for all traffic, mTLS for service-to-service | Data is protected during transport, even on internal networks |
| Data Loss Prevention (DLP) | Scan outbound data for PII, secrets, or classified content | Prevent intentional or accidental data exfiltration |
| Access transparency | Log every data access; alert on anomalous patterns | Know who accessed what data, when, and from where |
| Tokenization / masking | Replace sensitive data with tokens; show masked data in non-privileged contexts | Reduce exposure surface without removing data utility |
| Retention and deletion | Automated data lifecycle management, right-to-deletion workflows | Old data is a liability; delete it when no longer needed |

---