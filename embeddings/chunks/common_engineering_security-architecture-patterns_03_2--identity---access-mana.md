---
source: "common/engineering/security-architecture-patterns.md"
title: "Security Architecture Patterns"
heading: "2. Identity & Access Management"
category: "common-vuln"
language: "common"
severity: "medium"
tags: [access, common-vuln, encryption, identity, logging, monitoring, network, security, segmentation, strategies]
chunk: 3/7
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