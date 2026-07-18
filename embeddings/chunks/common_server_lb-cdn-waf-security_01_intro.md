---
source: "common/server/lb-cdn-waf-security.md"
title: "Load Balancer / CDN / WAF Security — Misconfiguration, Origin Exposure, Rule Bypass"
heading: "intro"
category: "common-vuln"
language: "common"
severity: "high"
tags: [checklist, common, common-vuln, cves, explanation, mistakes, prevention, real, secure, vulnerability]
chunk: 1/8
---

# Load Balancer / CDN / WAF Security — Misconfiguration, Origin Exposure, Rule Bypass

**Severity:** High  
**CWE:** CWE-200 (Exposure of Sensitive Information), CWE-287 (Improper Authentication), CWE-16 (Configuration), CWE-400 (Uncontrolled Resource Consumption)  
**AI Risk:** Medium — AI often generates overly permissive WAF rules, disables security features, misconfigures TLS modes, or exposes origin IP  
**OWASP Top 10:2021:** A05 — Security Misconfiguration, A01 — Broken Access Control  

---