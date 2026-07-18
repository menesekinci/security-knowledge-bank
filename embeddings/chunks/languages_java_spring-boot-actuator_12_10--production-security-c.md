---
source: "languages/java/spring-boot-actuator.md"
title: "Spring Boot Actuator Security Deep Dive"
heading: "10. Production Security Checklist"
category: "language-vuln"
language: "java"
severity: "medium"
tags: [custom, cve-2025-48927, endpoint, endpoints, full, heap, java, language-vuln, overview]
chunk: 12/13
---

## 10. Production Security Checklist

- [ ] `include: "health,info,metrics"` — no wildcards
- [ ] `heapdump.enabled: false`
- [ ] `env.enabled: false` (or `show-values: NEVER`)
- [ ] `shutdown.enabled: false`
- [ ] `configprops.enabled: false`
- [ ] Actuator on separate port (8081) bound to localhost
- [ ] HTTPS enforced
- [ ] Admin role required for sensitive endpoints
- [ ] NetworkPolicy / firewall restricting actuator access
- [ ] Random base-path for actuator
- [ ] Regular security audits of actuator configuration

---