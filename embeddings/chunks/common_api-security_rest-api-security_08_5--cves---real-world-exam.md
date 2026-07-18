---
source: "common/api-security/rest-api-security.md"
title: "REST API Security"
heading: "5. CVEs & Real-World Examples"
category: "api-security"
language: "common"
severity: "medium"
tags: [api-security, authentication, limiting, methods, overview, pagination, rate, security, table]
chunk: 8/9
---

## 5. CVEs & Real-World Examples

### CVE-2022-23540 — jsonwebtoken Signature Validation Bypass
- **Description**: In `jsonwebtoken` `<= 8.5.1`, calling `jwt.verify()` without specifying `algorithms` and with a falsy secret/key defaults to the `none` algorithm, so an unsigned/tampered token is accepted — a signature-validation bypass leading to auth bypass or privilege escalation.
- **Affected**: jsonwebtoken (npm) <= 8.5.1
- **CVSS**: 7.6 (High)
- **Fix**: Upgrade to jsonwebtoken 9.0.0+ (drops default `none` support); always pass an explicit `algorithms` allowlist and a strong secret
- **Source**: https://nvd.nist.gov/vuln/detail/CVE-2022-23540

### CVE-2025-45768 — PyJWT Weak Encryption (DISPUTED)
- **Description**: A reported weak-encryption issue in PyJWT v2.10.1 (CWE-311). **Disputed by the supplier**: the key length is chosen by the application using the library, so the maintainers consider key strength an application-level responsibility rather than a library flaw.
- **Affected**: PyJWT 2.10.1 (disputed)
- **CVSS**: Not authoritatively scored (entry is disputed)
- **Fix**: No official patch — this is disputed; applications should enforce sufficiently strong keys themselves
- **Source**: https://nvd.nist.gov/vuln/detail/CVE-2025-45768

### CVE-2025-8625 — Hard-coded JWT Secret in WordPress REST API
- **Description**: CopyPress REST API plugin uses a hard-coded JWT signing key when no secret is set, allowing unauthenticated attackers to forge tokens
- **Affected**: CopyPress REST API 1.1 - 1.2 (WordPress)
- **CVSS**: 9.8 (Critical)
- **Fix**: Require administrators to set a unique secret key; never fall back to hardcoded values
- **Source**: https://github.com/Nxploited/CVE-2025-8625

### CVE-2024-47654 — Missing Rate Limiting on OTP API
- **Description**: Shilpi Client Dashboard lacks rate limiting and CAPTCHA protection for OTP requests, enabling unlimited brute-force
- **Affected**: Shilpi Client Dashboard (various versions)
- **CVSS**: 7.5 (High)
- **Fix**: Implement per-IP and per-account rate limiting with CAPTCHA after N attempts
- **Source**: https://nvd.nist.gov/vuln/detail/cve-2024-47654

### CVE-2025-54576 — OAuth2-Proxy Authentication Bypass
- **Description**: Critical auth bypass in OAuth2-Proxy when `skip_auth_routes` is misconfigured, allowing unauthenticated access to protected routes
- **Affected**: OAuth2-Proxy (specific versions)
- **CVSS**: 9.1 (Critical)
- **Fix**: Proper validation of `skip_auth_routes` configuration; restrict to non-sensitive endpoints only
- **Source**: https://zeropath.com/blog/cve-2025-54576-oauth2-proxy-auth-bypass

### CVE-2025-27371 — OAuth 2.0 JWT Profile Ambiguity
- **Description**: Ambiguities in the JSON Web Token Profile for OAuth 2.0 Client Authentication mechanism allowing token confusion
- **Affected**: IETF OAuth 2.0 specifications and implementations
- **CVSS**: 6.9 (Medium)
- **Fix**: Implement explicit token type checking and audience validation
- **Source**: https://nvd.nist.gov/vuln/detail/CVE-2025-27371

---