---
source: "common/server/lb-cdn-waf-security.md"
title: "Load Balancer / CDN / WAF Security — Misconfiguration, Origin Exposure, Rule Bypass"
heading: "4. Real CVEs (Web-Verified)"
category: "common-vuln"
language: "common"
severity: "high"
tags: [checklist, common, common-vuln, cves, explanation, mistakes, prevention, real, secure, vulnerability]
chunk: 5/8
---

## 4. Real CVEs (Web-Verified)

| CVE ID | CVSS | Affected | Vulnerability | Category |
|--------|------|----------|--------------|----------|
| CVE-2017-15524 | 9.1 CRITICAL | Kemp Load Balancer <7.2.40.1 | Application Firewall Pack (AFP) bypass via HTTP POST request — WAF security feature bypass | WAF / LB |
| CVE-2020-22669 | 9.8 CRITICAL | ModSecurity OWASP CRS 3.2.0 | SQL injection bypass via comment characters and variable assignments in SQL syntax — WAF evasion | WAF |
| CVE-2023-38199 | 9.8 CRITICAL | OWASP CRS ≤3.3.4 | Multiple Content-Type headers bypass WAF detection on some platforms | WAF |
| CVE-2023-45132 | 9.8 CRITICAL | NAXSI WAF 1.3–<1.6 | X-Forwarded-For IP matching `IgnoreIP`/`IgnoreCIDR` rules allows WAF bypass (CWE-693) | WAF |
| CVE-2024-1019 | 8.6 HIGH | ModSecurity 3.0.0–3.0.11 | Percent-encoded path bypass — URL decoding inconsistency allows WAF evasion | WAF |
| CVE-2023-50969 | 9.8 CRITICAL | Imperva SecureSphere WAF 14.7.0.40 | WAF bypass via crafted POST request (different from CVE-2021-45468) | WAF |
| CVE-2022-25946 | 6.5 MED (NVD) / 8.7 HIGH (F5) | F5 BIG-IP Advanced WAF/ASM 11.6.x–16.1.x | Appliance Mode privilege-boundary flaw; authenticated Administrator bypass (CWE-354). NVD primary scores 6.5; F5 (CNA) scores 8.7 | WAF |
| CVE-2024-46982 | 7.5 HIGH | Next.js | CDN cache poisoning via crafted HTTP request to non-dynamic SSR route | CDN |
| CVE-2025-27415 | 7.5 HIGH | Nuxt <3.16.0 | CDN cache poisoning via crafted HTTP request behind CDN | CDN |
| CVE-2026-2836 | 8.1 HIGH | Pingora (Cloudflare) | HTTP proxy framework cache poisoning — default cache key construction flaw | CDN / LB |
| CVE-2026-2833 | 9.1 CRITICAL | Pingora (Cloudflare) | HTTP request smuggling via HTTP/1.1 Upgrade header handling | LB / CDN |
| CVE-2026-2835 | 9.1 CRITICAL | Pingora (Cloudflare) | HTTP request smuggling via HTTP/1.0 and Transfer-Encoding parsing | LB / CDN |
| CVE-2025-66490 | 6.5 MEDIUM | Traefik 2.11.31 through ≤3.6.2 (fixed in 2.11.32 / 3.6.3) | Path normalization bypass — URL-encoded restricted characters in PathPrefix/Path/PathRegex matchers bypass routing rules (CWE-436) | LB |
| CVE-2024-8901 | 7.5 HIGH | AWS ALB Route Directive Adapter for Istio | OIDC authentication mechanism integration flaw in AWS ALB adapter | LB |
| CVE-2025-64525 | 6.5 MEDIUM | Astro <5.15.5 | Insecure use of `x-forwarded-proto` / `x-forwarded-port` headers — protocol downgrade behind CDN/LB | CDN / LB |
| CVE-2025-57816 | 7.5 HIGH | Fides <2.69.1 | IP-based rate limiting bypass behind CDNs, proxies or load balancers | CDN / LB / WAF |

---