# Security Architecture Patterns

> Engineering-focused reference on foundational security architecture patterns — network segmentation, identity & access management, encryption strategies, logging & monitoring, and API security architecture.

---

## 1. Network Segmentation

Network segmentation is the practice of dividing a network into smaller, isolated zones to limit lateral movement and contain breaches. In modern architectures this spans physical networks, cloud VPCs, and Kubernetes clusters.

### 1.1 VPC Design (Cloud)

Every cloud deployment should follow a least-privilege network topology:

| Component | Purpose | Security Properties |
|---|---|---|
| **Public subnets** | Load balancers, bastion hosts, NAT gateways | Direct internet ingress/egress only; no application servers |
| **Private subnets** | Application servers, databases, cache layers | No direct internet route; outbound via NAT only |
| **Isolated subnets** | Secrets stores, internal registries, CA servers | No internet route at all (air-gapped at network layer) |
| **VPN / Direct Connect** | Admin access, hybrid connectivity | Encrypted tunnel; terminated on a dedicated VPN subnet |

**Key design decisions:**

- **NAT vs. private link:** Outbound traffic from private subnets goes through a NAT gateway (shared) or NAT instance (cost-sensitive). For service-to-service across accounts, prefer VPC endpoints (AWS PrivateLink, GCP Private Service Connect) — they keep traffic off the public internet entirely.
- **VPC peering / Transit Gateway:** Cross-VPC traffic should be explicitly routed through a central inspection VPC that hosts firewalls and IDS/IPS. Never peer VPCs directly without a central hub for logging and filtering.
- **Flow logs:** Enable VPC flow logs on every subnet. Aggregate to a SIEM for anomaly detection (unexpected egress, port scans, lateral movement).

### 1.2 Micro-Segmentation (Kubernetes)

In Kubernetes, the traditional perimeter model collapses — every pod can talk to every other pod by default. Micro-segmentation re-establishes per-workload isolation.

**Network Policies (native K8s):**
```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: api-allow-frontend
spec:
  podSelector:
    matchLabels:
      app: api-server
  policyTypes:
  - Ingress
  ingress:
  - from:
    - podSelector:
        matchLabels:
          app: frontend
    ports:
    - protocol: TCP
      port: 8080
```

- Default-deny ingress + egress policies should be applied to every namespace.
- Policies follow the pod identity (labels), not IPs — this is the architectural win over traditional firewall rules.
- **Gotcha:** Most CNI plugins enforce egress policies only at the node level; test egress rules thoroughly.

**Service Mesh (Istio / Linkerd):**
A service mesh provides identity-based segmentation at L7:

- **mTLS between all services:** Every sidecar proxy gets a SPIFFE-compliant identity certificate. Traffic without a valid identity is rejected.
- **Authorization policies:** Beyond network rules, you enforce "service A can only call endpoint X on service B with verb GET."
- **Observability:** The mesh exports traffic logs, metrics, and spans — invaluable for auditing who talked to whom.

**When to use what:**
- Network Policies for basic L3/L4 isolation (faster, simpler, no sidecar overhead).
- Service mesh when you need L7 authorization, mTLS automation, or observability at the service call level.
- Both together for defense-in-depth: network policies are the blast-radius floor, mesh policies are the fine-grained ceiling.

### 1.3 DMZ Patterns for Web Applications

The classic DMZ (demilitarized zone) lives on in cloud architectures:

```
Internet → WAF/CDN → Public LB → App Instances (DMZ subnet) → Private LB → Internal Services
```

**Three-tier DMZ:**
1. **Edge tier:** CloudFront/Cloudflare + WAF. Terminates TLS, blocks layer-7 attacks (SQLi, XSS) before they reach your origin.
2. **Presentation tier:** Public-facing application servers in a DMZ subnet. No direct database access — only calls to the API tier.
3. **Data tier:** Internal services, databases, caches — in a private subnet with no ingress from the internet. Only the presentation tier can reach them, and only on specific ports.

**Reverse proxy pattern:**
All external traffic lands on a reverse proxy (nginx, HAProxy, Envoy) that performs TLS termination, rate limiting, and request validation before forwarding to application servers. The proxy itself should run on hardened, minimal OS images.

---

## 2. Identity & Access Management

### 2.1 Identity Boundaries

An identity boundary is the logical trust domain where authentication and authorization decisions are made. Knowing where the boundary lives is critical:

- **User identity boundary:** Usually an IdP (Okta, Azure AD, Keycloak). Authentication happens here; authorization flows downstream as tokens.
- **Service identity boundary:** In a monolithic era, services trusted each other by network location. Today, services carry cryptographic identities (mTLS certificates, JWT assertions, SPIFFE IDs).
- **Machine identity boundary:** CI/CD agents, build runners, and automation tools need their own non-human identities with scoped permissions.

**Principle:** Never cross identity boundaries with a shared secret. If two services need to communicate, they should each present independent credentials — not share a single API key.

### 2.2 Service-to-Service Authentication

| Method | Use Case | Strength |
|---|---|---|
| **mTLS** | Service mesh, gRPC, internal APIs | Very high — mutual certificate verification |
| **OAuth2 Client Credentials** | API gateway → backend services | High — token expiry, scoped |
| **SPIFFE / SPIRE** | Dynamic workloads in K8s | Very high — short-lived, workload-attested |
| **API keys + HMAC** | Legacy systems, simple cases | Medium — static keys are hard to rotate |
| **JWT signed with shared secret** | Internal microservices (simple) | Medium-low — secret distribution is the weak link |

**mTLS in practice:**
- Each service gets a certificate from an internal CA (or SPIRE).
- The connecting service presents its cert; the receiving service validates it against the CA bundle.
- Certificate revocation is handled via CRLs or short-lived certs (SPIRE default: 1-hour TTL).
- **Warning:** mTLS is authentication, not authorization. The cert proves *who* the caller is; you still need a policy to decide what the caller can do.

**OAuth2 Client Credentials flow:**
- Service A obtains a token from the authorization server using its client ID + secret.
- Token is passed in the `Authorization: Bearer` header to Service B.
- Service B validates the token signature (using the auth server's JWKS endpoint) and checks scopes.
- Tokens should be short-lived (15 minutes) with refresh rotation.

### 2.3 Human vs. Machine Identities

Never treat human and machine identities interchangeably:

| Dimension | Human Identity | Machine Identity |
|---|---|---|
| **Lifecycle** | Hire/terminate/role-change | Deploy/scale/destroy |
| **Credential type** | Password + MFA | Short-lived certs, tokens |
| **Auth mechanism** | Interactive (SSO, WebAuthn) | Automated (mTLS, client_credentials) |
| **Authorization** | RBAC, ABAC based on role | Scoped to workload identity |
| **Secrets management** | Password manager | Vault, Secrets Manager, K8s secrets |

**Anti-pattern:** Embedding a human's personal access token in a CI/CD pipeline. If that human leaves, the pipeline breaks — and you may not discover it until a Friday night deploy fails.

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

## 4. Logging & Monitoring Architecture

### 4.1 Centralized Logging

Centralized logging collects logs from every service, host, and network device into a single searchable platform.

| Platform | Strengths | Weaknesses |
|---|---|---|
| **ELK (Elasticsearch, Logstash, Kibana)** | Open source, highly customizable, full-text search | Operational overhead, scaling Elasticsearch |
| **Loki (Grafana)** | Designed for K8s, cheap log ingestion, integrates with Prometheus | Limited structured query, younger ecosystem |
| **Datadog / Splunk** | Managed, out-of-the-box integrations, AI-driven alerts | Cost (especially at high volume), vendor lock-in |

**Log categories and retention:**
| Category | Examples | Retention | Cost sensitivity |
|---|---|---|---|
| **Debug logs** | Application traces, verbose request logs | 7–30 days | High — largest volume |
| **Operational logs** | Access logs, error rates, latency | 30–90 days | Medium |
| **Audit logs** | Auth events, permission changes, data access | 1–7 years (compliance) | Low — small volume, high value |

### 4.2 Audit Trails vs. Debugging Logs

These serve fundamentally different purposes and should be treated differently:

| Dimension | Audit Trail | Debug Log |
|---|---|---|
| **Purpose** | Non-repudiation, compliance, forensic investigation | Troubleshooting, performance analysis |
| **Content** | Who did what, when, from where, to what resource | Variable dumps, stack traces, timing data |
| **Immutability** | Must be append-only, tamper-evident | Can be overwritten or truncated |
| **Trigger** | Defined security events (auth, admin actions) | Every request or deterministic sample |
| **Format** | Structured (JSON, CEF) with schema enforcement | Semi-structured or freeform |
| **Access** | Restricted (read-only for most engineers) | Broad (anyone debugging) |

**Rule of thumb:** If the log record would hold up in court or during an audit, it's an audit trail. If it helps you find a bug, it's a debug log. Never put debug-log verbosity into an audit trail — the signal drowns in noise.

### 4.3 Log Integrity

Logs are evidence — they must be trustworthy. An attacker who compromises a system should not be able to erase their tracks by modifying logs.

**Forwarding (immutable pipeline):**
```
App → Filebeat/Fluentd → Message Queue (Kafka) → SIEM → WORM Storage
```
- Logs should be forwarded off the host immediately (syslog-ng, Filebeat, Fluentd).
- Buffering on the host is acceptable (for network blips), but the primary store should be the SIEM, not the local disk.
- Use TLS for log shipping to prevent tampering in transit.

**WORM (Write Once, Read Many) storage:**
- Final destination for audit logs should be immutable: S3 Object Lock, Azure Immutable Blob, physical WORM media.
- Retention policy is enforced by the storage layer, not by application code (apps can be hacked; the storage layer's immutability is harder to bypass).
- For compliance (PCI DSS, SOC 2, HIPAA), WORM storage with a retention period of at least 1 year is often required.

**Log integrity verification:**
- Cryptographic signing of log entries (e.g., syslog with TLS, or per-entry HMAC).
- Periodic integrity checks: compute a hash of the log range and compare against a stored value.
- Chain hashing (each entry includes the hash of the previous entry) — similar to a blockchain. If any entry is modified, its hash changes and all subsequent hashes break.

---

## 5. API Security Architecture

### 5.1 Gateway Patterns

An API gateway serves as the single entry point for all external API traffic, handling cross-cutting security concerns:

```
Client → CDN/WAF → API Gateway → Backend Services
                     ├── Auth (validate tokens, API keys)
                     ├── Rate limiting (per-client, per-endpoint)
                     ├── Request transformation (header injection, size limits)
                     ├── Validation (schema, content-type enforcement)
                     └── Logging (audit trail of all API calls)
```

**Security responsibilities the gateway should own:**
- **Authentication:** Validate JWT signatures, API key hashes, OAuth tokens *before* the request reaches your application code.
- **Rate limiting:** Per-client (by API key or IP), per-endpoint. Use token bucket or sliding window algorithms. Return `429 Too Many Requests` with a `Retry-After` header.
- **Request validation:** Enforce content-type, max body size, required headers. Block malformed requests at the edge.
- **Header injection:** Add correlation IDs (`X-Request-Id`), tracing headers, and internal routing info — but strip client-supplied internal headers.
- **TLS termination:** The gateway is the right place to manage certificates, not individual services.

**Gateway options:** Kong, Envoy, AWS API Gateway, Azure API Management, NGINX Plus, KrakenD.

### 5.2 Backend-for-Frontend (BFF) Pattern

A BFF is a dedicated backend per client type (web, mobile, third-party). It acts as a security intermediary:

```
Web Client → Web BFF → Internal APIs
Mobile App → Mobile BFF → Internal APIs
```

**Security advantages of BFF:**
- **No client-side secrets:** The BFF holds API keys, client credentials, and session state. The browser/app never sees them.
- **Scoped session:** The BFF issues a short-lived session cookie (HttpOnly, Secure, SameSite=Strict) that is not accessible to JavaScript — eliminating XSS-based token theft.
- **Request shaping:** The BFF gathers only the data the specific client needs — no over-fetching, no exposure of internal entity models.
- **Rate limiting per client type:** Mobile clients get different rate limits than web scrapers.

**Anti-pattern:** A single BFF for all clients. Web and mobile have different security postures (cookie-based vs. token-based auth, different CORS requirements). A shared BFF ends up with the lowest-common-denominator security.

### 5.3 API Versioning and Deprecation Security

API versioning isn't just a developer experience concern — it's a security concern:

- **Deprecated endpoints = attack surface.** Every old version you keep is a potential vulnerability window. If v1 doesn't validate a field that v2 does, attackers will target v1.
- **Version sunset policy:** Define a firm deprecation timeline (e.g., 6 months notice, then block). Enforce it at the gateway level — return `410 Gone` or `301` to the current version.
- **Version in the URL vs. header:** URL versioning (`/v1/users`) is simpler to log and audit. Header versioning (`Accept: application/vnd.api+json;version=2`) is cleaner but harder to monitor.
- **Backward-compatible changes only:** Adding fields is safe; removing or changing field types is a breaking change. Breaking changes require a new version and old-version deprecation.

**Security checklist for deprecated versions:**
- [ ] Disallow new client registration on deprecated versions.
- [ ] Apply enhanced monitoring and alerting (older versions are more likely targeted).
- [ ] Remove deprecated endpoints from documentation and SDK generation.
- [ ] Cut off traffic at the gateway after the sunset date, not at the application level.

---

## 6. References

### Industry Frameworks

| Framework | Focus | URL |
|---|---|---|
| **AWS Well-Architected Framework — Security Pillar** | Cloud security architecture on AWS | https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/ |
| **Google Cloud Architecture Framework — Security, Privacy, and Compliance** | Security architecture on GCP | https://cloud.google.com/architecture/framework/security |
| **Azure Well-Architected Framework — Security** | Security architecture on Azure | https://learn.microsoft.com/en-us/azure/well-architected/security/ |
| **CIS Critical Security Controls** | Baseline controls prioritized by effectiveness | https://www.cisecurity.org/controls/ |
| **NIST SP 800-207 (Zero Trust Architecture)** | Zero trust design principles | https://csrc.nist.gov/publications/detail/sp/800-207/final |

### Further Reading (Internal Knowledge Bank)

- [CSP Deep Dive](../csp-deep.md) — Content Security Policy architecture and deployment
- [CORS Deep Dive](../cors-deep.md) — Cross-origin security for API gateways
- [OAuth2 Security](../oauth2-security.md) — OAuth2 flows, token handling, and best practices
- [OIDC/SAML Security](../oidc-saml-security.md) — Identity federation architecture
- [MCP Security](../mcp-security.md) — Model Context Protocol security architecture
- [Incident Response](../incident-response.md) — Response procedures when segmentation fails
