---
source: "languages/java/spring-boot-actuator.md"
title: "Spring Boot Actuator Security Deep Dive"
category: "language-vuln"
language: "java"
chunk: 4
total_chunks: 13
heading: "2. Env Endpoint — Environment Variable Leakage"
---

## 2. Env Endpoint — Environment Variable Leakage

### The Danger

The `/actuator/env` endpoint exposes ALL environment variables, system properties, and configuration values — including database passwords, API keys, and cloud credentials.

**Vulnerable Code:**
```yaml
# application.yml — 💀 Env endpoint exposed
management:
  endpoints:
    web:
      exposure:
        include: "env"   # 💀 Exposes ALL environment variables
```

**Secure Code:**
```yaml
# ✅ SECURE — Disable env endpoint or restrict with keys pattern
management:
  endpoints:
    web:
      exposure:
        include: "health,info"
  endpoint:
    env:
      enabled: false                          # ✅ Disable completely
      # OR — Only show specific keys:
      # show-values: WHEN_AUTHORIZED
      # keys-to-sanitize: "password,secret,key,token,.*credentials.*"
```

```java
// ✅ SECURE — Sanitize sensitive values in env endpoint
@Configuration
public class ActuatorSecurityConfig {

    @Bean
    public EnvironmentEndpointCustomizer envCustomizer() {
        return configurer -> configurer.setKeysToSanitize(
            "password", "secret", "key", "token", 
            ".*credentials.*", ".*api.*key.*", 
            "spring.datasource.*"
        );
    }
}
```

---