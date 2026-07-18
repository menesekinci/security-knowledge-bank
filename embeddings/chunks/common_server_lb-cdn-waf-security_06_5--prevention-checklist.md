---
source: "common/server/lb-cdn-waf-security.md"
title: "Load Balancer / CDN / WAF Security — Misconfiguration, Origin Exposure, Rule Bypass"
heading: "5. Prevention Checklist"
category: "common-vuln"
language: "common"
severity: "high"
tags: [checklist, common, common-vuln, cves, explanation, mistakes, prevention, real, secure, vulnerability]
chunk: 6/8
---

## 5. Prevention Checklist

### Cloudflare
- [ ] **Always proxy DNS records** (orange-cloud) — never grey-cloud for web-facing origins
- [ ] **Set SSL/TLS to Full (Strict)** — never Flexible mode
- [ ] **Enable WAF managed rules** — at minimum OWASP Top 10 + Cloudflare Managed
- [ ] **Set Security Level to High or I'm Under Attack** mode during threats
- [ ] **Enable Bot Fight Mode** or Super Bot Fight Mode
- [ ] **Configure Authenticated Origin Pulls** — TLS client certificate validation
- [ ] **Use API Shield** for API endpoints (schema validation, mTLS)
- [ ] **Enable Rate Limiting** rules for login, registration, and API endpoints
- [ ] **Set proper Cache Keys** — vary by Authorization header for authenticated content

### AWS WAF
- [ ] **Default action should be BLOCK** — not allow (principle of least privilege)
- [ ] **Enable AWS Managed Rule Groups** — CommonRuleSet, SQLDatabase, AdminProtection, KnownBadInputs
- [ ] **Implement rate-based rules** — at least 2000 requests per 5 minutes per IP
- [ ] **Enable WAF logging** to CloudWatch Logs or S3
- [ ] **Redact sensitive fields** in logs (Authorization, Cookie, Set-Cookie)
- [ ] **Use label-based rule ordering** — ensure blocking rules evaluate before allow rules
- [ ] **Implement IP reputation lists** — AWSManagedRulesAnonymousIpList, AWSManagedRulesAmazonIpReputationList
- [ ] **Test rules in COUNT mode first** before switching to BLOCK

### Load Balancers
- [ ] **Use dedicated health check endpoints** separate from main application
- [ ] **Restrict health check by source IP** (internal ranges only) or shared secret
- [ ] **Never expose admin/monitoring panels** (HAProxy stats, Nginx status) to internet
- [ ] **Change default admin credentials** on load balancer management interfaces
- [ ] **Use separate internal ports** for health checks and admin interfaces
- [ ] **Implement proper path normalization** — avoid path traversal bypasses
- [ ] **Enable access logs** with adequate retention

### CDN
- [ ] **Set `Cache-Control: private`** for authenticated content — never cache user-specific data
- [ ] **Use `Vary: Authorization`** header for partially cacheable authenticated content
- [ ] **Set short TTLs** for dynamic API responses (60–300 seconds)
- [ ] **Never cache admin pages, dashboards, or user profile pages**
- [ ] **Implement cache key customization** — include auth-relevant headers
- [ ] **Test cache purge mechanisms** — ensure stale content can be removed quickly
- [ ] **Use origin pull** — prevent direct-to-origin access bypassing CDN

---