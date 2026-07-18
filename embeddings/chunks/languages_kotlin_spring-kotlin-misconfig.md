---
source: "languages/kotlin/spring-kotlin-misconfig.md"
title: "🟠 Spring Boot Kotlin Misconfiguration"
category: "language-vuln"
language: "kotlin"
severity: "high"
tags: [code, explanation, kotlin, language-vuln, secure, severity, vulnerability, vulnerable]
---

# 🟠 Spring Boot Kotlin Misconfiguration

> **Category:** Security Misconfiguration / Broken Access Control  
> **Language:** Kotlin + Spring Boot  
> **Severity:** High to Critical  
> **CWE:** CWE-16 (Configuration), CWE-200 (Exposure of Sensitive Information), CWE-1188 (Insecure Default Initialization), CWE-306 (Missing Authentication for Critical Function)

## Severity / CWE

| Field | Value |
|-------|--------|
| **Severity** | 🟠 High–🔴 Critical |
| **Primary CWE** | CWE-16, CWE-200, CWE-306, CWE-1188, CWE-942 (Permissive CORS) |
| **OWASP** | A05:2021 Security Misconfiguration |

## Vulnerability Explanation

Kotlin Spring Boot apps share Java Spring footguns, with extra Kotlin-specific defaults:

1. **Open Actuator endpoints** — `env`, `heapdump`, `gateway`, `beans` expose secrets and lead to RCE chains.
2. **`spring.security` incomplete** — `permitAll` for `/api/**` left from prototypes; method security not enabled.
3. **CSRF disabled for “APIs”** while still using cookie sessions.
4. **CORS `*` with credentials** — reflected origin bugs in custom configs.
5. **Devtools / H2 console / swagger UI** enabled in production.
6. **Kotlin `lateinit` / non-null lies** — security filters skipped on error paths; null domain objects bypass checks.
7. **`data class` entities exposed via Spring Data REST** — full graph binding (see [data-class-copy.md](data-class-copy.md)).
8. **Jackson Kotlin module** polymorphic typing (`enableDefaultTyping` legacy) → deserialization gadgets.
9. **Secrets in `application.yml` committed**; multi-doc profiles wrong (`application-prod` never activated).
10. **Coroutine + security context** — `SecurityContext` not propagated to async/coroutine dispatchers → authz fail-open or fail-closed inconsistently.

## How AI / Vibe Coding Generates This

```
Prompt: "Spring Boot Kotlin REST API starter"
AI: spring-boot-starter-actuator without lockdown;
    SecurityFilterChain { authorizeHttpRequests { anyRequest.permitAll() } }
    springdoc + h2 console enabled;
    CORS allowCredentials true + allowedOrigin "*"
```

AI prioritizes “it runs in browser from Vite on :5173” over least privilege.

## Vulnerable Code

```kotlin
// 💀 Wide open security
@Bean
fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
    http.csrf { it.disable() }
        .authorizeHttpRequests { it.anyRequest().permitAll() }
    return http.build()
}

// application.yml 💀
management:
  endpoints:
    web:
      exposure:
        include: "*"   # heapdump, env, shutdown...
  endpoint:
    env:
      show-values: always

// 💀 CORS
@Bean
fun cors(): WebMvcConfigurer = object : WebMvcConfigurer {
    override fun addCorsMappings(registry: CorsRegistry) {
        registry.addMapping("/**")
            .allowedOrigins("*")
            .allowCredentials(true) // invalid/dangerous combo
    }
}

// 💀 Spring Data REST exporting entities
@RepositoryRestResource
interface UserRepo : JpaRepository<UserEntity, Long>
```

## Secure Fix

```kotlin
@Bean
fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
    http
        .csrf { /* enable for cookie sessions; or use pure bearer tokens carefully */ }
        .authorizeHttpRequests {
            it.requestMatchers("/actuator/health", "/actuator/info").permitAll()
            it.requestMatchers("/actuator/**").hasRole("ADMIN")
            it.requestMatchers("/api/admin/**").hasRole("ADMIN")
            it.requestMatchers("/api/**").authenticated()
            it.anyRequest().denyAll()
        }
        .oauth2ResourceServer { it.jwt { } } // example
        .sessionManagement {
            it.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
        }
    return http.build()
}

// application-prod.yml
management:
  endpoints:
    web:
      exposure:
        include: health,info
  endpoint:
    health:
      show-details: when_authorized

// CORS: explicit origins, no *
registry.addMapping("/api/**")
    .allowedOrigins("https://app.example.com")
    .allowedMethods("GET", "POST", "PUT", "DELETE")
    .allowCredentials(true)

// Do not export JPA entities via Data REST without projections + security
```

Coroutine note: propagate security context explicitly (`SecurityContextHolder` + thread locals are not magic across coroutine dispatchers). Prefer reactor/coroutine integrations documented for Spring Security 6.

## Prevention Checklist

- [ ] Actuator: expose only health/info publicly; secure or disable the rest
- [ ] Default deny in `SecurityFilterChain`; no global `permitAll`
- [ ] Separate DTOs from JPA entities; avoid open Data REST
- [ ] CORS allow-list exact origins; never `*` + credentials
- [ ] Disable H2 console, devtools, debug detail in prod profiles
- [ ] Secrets via env / vault — not git YAML
- [ ] Enable method security (`@PreAuthorize`) for sensitive ops
- [ ] CSRF strategy matches auth mode (cookie vs bearer)
- [ ] Jackson: no default polymorphic typing on untrusted JSON
- [ ] Test security with `@WithMockUser` / integration tests for 401/403
- [ ] Review Kotlin nullability vs filter order (exception handlers must not leak stack traces)
- [ ] Configure SPA/API CORS in one documented place

## Real CVEs / Case References

| CVE / Advisory | Summary | Link |
|----------------|---------|------|
| **Spring Actuator real-world breaches** | Misconfigured actuators historically exposed env properties (DB passwords, cloud keys) leading to full compromise — pattern, many write-ups | Search “Spring Boot Actuator heapdump RCE”; bank Java: spring-boot-actuator materials if present under `languages/java/` |
| **CVE-2022-22965 (Spring4Shell)** | Class loader / data binding RCE on certain Spring MVC setups — shows risk of binder + vulnerable runtime | https://nvd.nist.gov/vuln/detail/CVE-2022-22965 |
| **CVE-2013-0156** | Framework request parsing RCE class lesson for “convenient defaults” | https://nvd.nist.gov/vuln/detail/CVE-2013-0156 |
| **CVE-2020-1147** | .NET DataSet XML RCE — cross-ecosystem reminder: platform deserializers + default trust kill apps | https://nvd.nist.gov/vuln/detail/CVE-2020-1147 |

Kotlin does not remove Spring binder/actuator risk — it often **hides** it behind concise config DSLs that AI copies unsafely.

## Vibe Coding Red Flags

| Red flag | Risk |
|----------|------|
| `anyRequest().permitAll()` | Auth bypass |
| `include: "*"` actuators | Secret dump / attack pivot |
| `csrf.disable()` + cookie auth | CSRF account takeover |
| `allowedOrigins("*")` + credentials | Cross-site data theft |
| `@RepositoryRestResource` on User | Mass assignment / IDOR API |
| H2 console in prod YAML | Instant DB access |
| Stack traces in `server.error.include-stacktrace: always` | Info leak |
| JWT parse without signature verify (custom) | Auth bypass |
| Security context ignored in coroutines | Intermittent authz bugs |

**Prompt:**  
*“Spring Security default deny. Lock actuator to health/info. No permitAll on /api. Explicit CORS origins. Separate DTOs from entities. Prod profile disables H2/devtools. Never expose heapdump/env.”*

---

**Severity: 🟠 High–🔴 Critical** — full app compromise via misconfig.  
**CWE: CWE-16 / CWE-200 / CWE-306**
