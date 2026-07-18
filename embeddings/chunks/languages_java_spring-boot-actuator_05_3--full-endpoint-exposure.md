---
source: "languages/java/spring-boot-actuator.md"
title: "Spring Boot Actuator Security Deep Dive"
heading: "3. Full Endpoint Exposure — `include: '*'`"
category: "language-vuln"
language: "java"
severity: "medium"
tags: [custom, cve-2025-48927, endpoint, endpoints, full, heap, java, language-vuln, overview]
chunk: 5/13
---

## 3. Full Endpoint Exposure — `include: "*"`

### Most Common Misconfiguration

**Vulnerable Code:**
```yaml
# application.yml — 💀 WILDCARD exposure — exposes ALL endpoints
management:
  endpoints:
    web:
      exposure:
        include: "*"   # 💀 Exposes: heapdump, env, configprops, shutdown, threaddump, etc.
```

**What Gets Exposed:**

| Endpoint | Exposure Risk |
|----------|---------------|
| `/actuator/heapdump` | 💀 Full JVM memory: credentials, tokens, PII |
| `/actuator/env` | 💀 Environment variables, passwords, API keys |
| `/actuator/configprops` | 💀 Configuration properties, internal URLs |
| `/actuator/threaddump` | 🟠 Thread state, stack traces, internal paths |
| `/actuator/beans` | 🟠 Application bean names, class info |
| `/actuator/loggers` | 🟠 Change log levels at runtime |
| `/actuator/shutdown` | 💀 Graceful shutdown of the application |

**Secure Code:**
```yaml
# ✅ SECURE — Explicit allowlist of safe endpoints
management:
  endpoints:
    web:
      exposure:
        include: "health,info,metrics,prometheus"  # ✅ Only safe endpoints
      exclude: "*"                                   # Block all others

# OR for comprehensive control:
management:
  endpoints:
    enabled-by-default: false     # ✅ Nothing enabled by default
  endpoint:
    health:
      enabled: true
      show-details: WHEN_AUTHORIZED  # ✅ Don't show health details publicly
    info:
      enabled: true
    metrics:
      enabled: true
    prometheus:
      enabled: true
```

---