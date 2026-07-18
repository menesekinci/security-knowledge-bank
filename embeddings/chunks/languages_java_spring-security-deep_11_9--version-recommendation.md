---
source: "languages/java/spring-security-deep.md"
title: "Spring Security Deep Dive"
heading: "9. Version Recommendations"
category: "language-vuln"
language: "java"
severity: "high"
tags: [chain, configuration, cors, cve-2025-41248, filter, java, language-vuln, oauth2, overview, pitfalls]
chunk: 11/13
---

## 9. Version Recommendations

| Framework | Version | Status |
|-----------|---------|--------|
| Spring Boot | 3.4.x | ✅ Latest stable |
| Spring Security | 6.4.11+ / 6.5.5+ | ✅ Patched against CVE-2025-41248 |
| Spring Framework | 6.2.11+ / 6.1.23+ / 5.3.45+ | ✅ Patched against CVE-2025-41249, CVE-2024-38819, CVE-2024-22262 |
| Spring Cloud (OAuth2) | 2024.0.x | ✅ Latest |

---