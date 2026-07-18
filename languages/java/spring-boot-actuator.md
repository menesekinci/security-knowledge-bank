# Spring Boot Actuator Security Deep Dive

> **Category:** Java / Spring Boot Security Knowledge Bank  
> **Focus:** Heap dump exposure, env endpoint, custom endpoints, sensitive data leakage  
> **Last Updated:** July 2026

---

## Overview

Spring Boot Actuator provides production-ready monitoring endpoints. However, misconfigured actuator endpoints are a primary source of data breaches, leaking credentials, API keys, cloud tokens, and entire JVM memory contents.

---

## 1. CVE-2025-48927 — Heap Dump Exposure (Telemessage)

**CVSS:** 5.3 (Medium) — Exploited in the wild (CISA KEV)  
**Affected:** TeleMessage service through 2025-05-05 (underlying issue in Spring Boot Actuator)  
**Description:** The TeleMessage service configured Spring Boot Actuator with an exposed heap dump endpoint at `/heapdump` without authentication. Attackers can download the JVM heap dump and extract credentials, API keys, tokens, and sensitive data from memory.

**Vulnerable Code:**
```yaml
# application.yml — 💀 Heap dump endpoint exposed without auth
management:
  endpoints:
    web:
      exposure:
        include: "*"       # 💀 ALL endpoints exposed
  endpoint:
    heapdump:
      enabled: true
      # 💀 No access restriction!
```

```java
// 💀 VULNERABLE — No security on actuator endpoints
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(auth -> auth
                .anyRequest().permitAll()  // 💀 No auth on any endpoint
            );
        return http.build();
    }
}
```

**Attack Flow:**
```
GET /actuator/heapdump  →  Downloads JVM heap dump (hprof)
# Then: jhat heapdump.hprof → Browse objects → Extract credentials
```

**Secure Code:**
```yaml
# application.yml — ✅ Minimal endpoint exposure
management:
  endpoints:
    web:
      exposure:
        include: "health,info,metrics,prometheus"  # ✅ Only safe endpoints
      base-path: "/internal/actuator"               # ✅ Custom path (obscurity)
  endpoint:
    heapdump:
      enabled: false         # ✅ Disabled in production
    env:
      enabled: false         # ✅ Disabled in production
    shutdown:
      enabled: false         # ✅ Always disabled
    configprops:
      enabled: false         # ✅ Disabled in production
  info:
    env:
      enabled: false         # ✅ Don't expose env in info
```

```java
// ✅ SECURE — Actuator endpoints restricted to admin role
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain actuatorFilterChain(HttpSecurity http) throws Exception {
        http
            .securityMatcher("/internal/actuator/**")
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/internal/actuator/health").permitAll()
                .requestMatchers("/internal/actuator/info").permitAll()
                .requestMatchers("/internal/actuator/metrics").permitAll()
                .anyRequest().hasRole("ACTUATOR_ADMIN")  // ✅ Admin role required
            )
            .httpBasic(Customizer.withDefaults());
        return http.build();
    }
}
```

**Source:**
- https://nvd.nist.gov/vuln/detail/cve-2025-48927
- https://www.wiz.io/blog/spring-boot-actuator-misconfigurations
- https://www.sentinelone.com/vulnerability-database/cve-2025-48927/

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

## 4. Custom Endpoints — Security Bypass

**Vulnerable Code:**
```java
// 💀 VULNERABLE — Custom endpoint without security
@Component
@Endpoint(id = "admin-ops")
public class AdminEndpoint {

    @ReadOperation
    public Map<String, Object> getAdminData() {
        return Map.of(
            "databaseUrl", dbConfig.getUrl(),
            "databasePassword", dbConfig.getPassword(),  // 💀 Exposing secrets
            "allUsers", userService.getAllUsers()
        );
    }

    @WriteOperation
    public void deleteUser(@Selector String userId) {
        userService.deleteUser(userId);  // 💀 No authorization check
    }
}
```

**Secure Code:**
```java
// ✅ SECURE — Custom endpoint with auth and data filtering
@Component
@Endpoint(id = "admin-ops")
public class AdminEndpoint {

    @ReadOperation
    public Map<String, Object> getAdminData(Authentication authentication) {
        // Check authorization
        if (!hasAdminRole(authentication)) {
            throw new AccessDeniedException("Admin access required");
        }
        
        return Map.of(
            "databaseUrl", dbConfig.getUrl()
            // ✅ Password excluded!
        );
    }

    @WriteOperation
    public void deleteUser(@Selector String userId, Authentication authentication) {
        if (!hasAdminRole(authentication)) {
            throw new AccessDeniedException("Admin access required");
        }
        
        if (!userService.exists(userId)) {
            throw new IllegalArgumentException("User not found");
        }
        
        userService.deleteUser(userId);
    }

    private boolean hasAdminRole(Authentication auth) {
        return auth != null && auth.getAuthorities().stream()
            .anyMatch(a -> a.getAuthority().equals("ROLE_ACTUATOR_ADMIN"));
    }
}
```

---

## 5. Network-Level Protection

### The Defense-in-Depth Approach

```yaml
# ✅ SECURE — Multi-layer actuator security
management:
  server:
    port: 8081                              # ✅ Different port (not exposed externally)
    address: 127.0.0.1                       # ✅ Only accessible from localhost
  endpoints:
    web:
      base-path: "/${ACTUATOR_SECRET_PATH}" # ✅ Randomized path from env variable
      exposure:
        include: "health,info"
```

```java
// ✅ SECURE — IP whitelist for actuator endpoints
@Configuration
public class ActuatorIpFilter {

    @Bean
    public FilterRegistrationBean<ActuatorIpWhitelistFilter> actuatorFilter() {
        FilterRegistrationBean<ActuatorIpWhitelistFilter> registration = 
            new FilterRegistrationBean<>();
        registration.setFilter(new ActuatorIpWhitelistFilter());
        registration.addUrlPatterns("/actuator/*");
        registration.setOrder(1);
        return registration;
    }

    static class ActuatorIpWhitelistFilter extends OncePerRequestFilter {
        private static final List<String> ALLOWED_IPS = Arrays.asList(
            "10.0.0.0/8",     // Internal network
            "172.16.0.0/12",  // Docker network
            "192.168.0.0/16"  // Local network
        );

        @Override
        protected void doFilterInternal(HttpServletRequest request,
                                       HttpServletResponse response,
                                       FilterChain chain) 
                throws ServletException, IOException {
            String remoteAddr = request.getRemoteAddr();
            if (isAllowed(remoteAddr)) {
                chain.doFilter(request, response);
            } else {
                response.sendError(HttpStatus.FORBIDDEN.value());
            }
        }
        
        private boolean isAllowed(String ip) {
            // Implement IP matching against ALLOWED_IPS
            return ALLOWED_IPS.stream()
                .anyMatch(cidr -> ipMatchesCidr(ip, cidr));
        }
    }
}
```

---

## 6. Kubernetes-Specific Protection

```yaml
# ✅ SECURE — Using Kubernetes NetworkPolicy
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: restrict-actuator
spec:
  podSelector:
    matchLabels:
      app: my-service
  policyTypes:
  - Ingress
  ingress:
  - from:
    - podSelector:
        matchLabels:
          app: monitoring
    ports:
    - port: 8081
      protocol: TCP
```

```yaml
# ✅ SECURE — Spring Boot with K8s readiness/liveness probes
management:
  endpoints:
    web:
      exposure:
        include: "health,info"
  endpoint:
    health:
      probes:
        enabled: true        # ✅ /health/readiness, /health/liveness
      group:
        readiness:
          include: "db,diskSpace"
        liveness:
          include: "ping"
```

---

## 7. CVE Roundup

| CVE | CVSS | Affected | Type | Notes |
|-----|------|----------|------|-------|
| CVE-2025-48927 | 5.3 | Spring Boot Actuator (TeleMessage) | Heap Dump Exposure | Exploited in the wild (CISA KEV) |
| CVE-2023-20873 | 9.8 | Spring Boot 2.5.x–2.7.10, 3.0.0–3.0.5 | Security bypass | Actuator health-check bypass on Cloud Foundry |
| CVE-2023-34055 | 6.5 | Spring Boot 2.7.0-2.7.17, 3.0.0-3.0.12, 3.1.0-3.1.5 | Denial of Service | Requires spring-boot-actuator on classpath |

---

## 8. Version Recommendations

| Framework | Version | Status |
|-----------|---------|--------|
| Spring Boot | 3.4.x | ✅ Latest |
| Spring Boot 2.7 (LTS) | 2.7.18+ | ⚠️ End of support Oct 2025 |
| Spring Boot 3.3 | 3.3.x | ✅ Active maintenance |

---

## 9. Common AI-Produced Misconfigurations

1. **`management.endpoints.web.exposure.include: "*"`** — Most common wildcard exposure
2. **No authentication on actuator endpoints** — Open to anyone who finds them
3. **Heap dump left enabled** — Full JVM memory downloadable (CVE-2025-48927)
4. **`/env` endpoint exposing credentials** — Database passwords, API keys
5. **`/configprops` showing internal URLs and secrets**
6. **Custom endpoints without authorization checks**
7. **Actuator on default port (8080) with no IP restriction**
8. **`show-details: ALWAYS` on health endpoint** — Database status, disk space
9. **Loggers endpoint writable** — Allows runtime log level changes
10. **Spring Boot 1.x actuator** — `/dump` and `/trace` had no auth by default

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

## Verification / Source URLs

- Wiz Research: Spring Boot Actuator Misconfigurations: https://www.wiz.io/blog/spring-boot-actuator-misconfigurations
- NVD CVE-2025-48927: https://nvd.nist.gov/vuln/detail/cve-2025-48927
- Spring Boot Actuator Docs: https://docs.spring.io/spring-boot/reference/actuator/index.html
- Securing Spring Boot Actuator (Syscrest): https://www.syscrest.com/2025/02/securing-spring-boot-actuator/
- Spring Boot Actuator Security Guide: https://docs.spring.io/spring-boot/reference/actuator/security.html
- OWASP REST Security Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html
- Tenable: Spring Boot Actuator Sensitive Endpoints: https://www.tenable.com/plugins/was/113205
