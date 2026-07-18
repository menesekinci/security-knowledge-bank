# 🟠 Spring Boot Misconfiguration

## Example (Dangerous)
```java
// 💀 VULNERABLE — Actuator exposed:
// application.properties:
// management.endpoints.web.exposure.include=*
// management.endpoints.web.exposure.include=env,beans,heapdump

// /actuator/env → Environment variables (including AWS keys!)
// /actuator/heapdump → The entire heap (everything in memory!)
// /actuator/beans → All beans
```

## Secure Configuration
```properties
# ✅ SECURE:
# Expose ONLY health + info. Do NOT also set exposure.exclude=* —
# exclude takes precedence over include, so it would suppress health/info too.
management.endpoints.web.exposure.include=health,info
management.endpoint.health.show-details=never
info.app.name=MyApp
info.app.version=1.0.0
```

## Common Mistakes the AI Makes
- Leaving DevTools in production (`spring-boot-devtools`)
- Default secrets (`spring.security.user.password`)
- Leaving the H2 console open in production
- Opening CORS to everyone

---

**Severity: 🟠 High** — Information leakage, potential RCE.
