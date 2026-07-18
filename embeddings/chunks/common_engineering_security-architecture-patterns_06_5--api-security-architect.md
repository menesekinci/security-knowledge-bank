---
source: "common/engineering/security-architecture-patterns.md"
title: "Security Architecture Patterns"
heading: "5. API Security Architecture"
category: "common-vuln"
language: "common"
severity: "medium"
tags: [access, common-vuln, encryption, identity, logging, monitoring, network, security, segmentation, strategies]
chunk: 6/7
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