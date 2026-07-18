# Spring Security Deep Dive

> **Category:** Java / Spring Security Knowledge Bank  
> **Focus:** Filter chain ordering, @PreAuthorize bypass, CORS config, OAuth2 pitfalls  
> **Last Updated:** July 2026

---

## Overview

Spring Security is a powerful but complex framework. Misconfiguration of filter chains, annotation security on parameterized types, and CORS/OAuth2 pitfalls are among the most common issues AI-generated Spring code introduces.

---

## 1. CVE-2025-41248 — @PreAuthorize Bypass on Parameterized Types

**CVSS:** 7.5 (High) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`  
**Affected:** Spring Security 6.4.0 – 6.4.10 and 6.5.0 – 6.5.4 (fixed in 6.4.11, 6.5.5)  
**Description:** Spring Security's annotation detection mechanism may not correctly resolve annotations on methods within type hierarchies that have a parameterized super type with unbounded generics. This can lead to authorization bypass on `@PreAuthorize` and other method-security annotations under `@EnableMethodSecurity`. The underlying annotation-resolution flaw is tracked in Spring Framework as CVE-2025-41249.

**Vulnerable Code:**
```java
// 💀 VULNERABLE — Generic base class with @PreAuthorize
public abstract class BaseService<T> {
    
    @PreAuthorize("hasRole('ADMIN')")
    public T getById(Long id) {
        return repository.findById(id).orElseThrow();
    }
}

// Concrete implementation — annotation may not be inherited
@Service
public class UserService extends BaseService<User> {
    // 💀 @PreAuthorize from BaseService may not apply here
    // due to parameterized type resolution failure
    @Override
    public User getById(Long id) {
        // 💀 Authorization check bypassed!
        return super.getById(id);
    }
}
```

**Secure Code:**
```java
// ✅ SECURE — Apply @PreAuthorize directly on concrete class methods
@Service
public class UserService extends BaseService<User> {
    
    @Override
    @PreAuthorize("hasRole('ADMIN')")  // ✅ Explicit annotation
    public User getById(Long id) {
        return super.getById(id);
    }
}

// ✅ OR — Upgrade to patched Spring Security versions
// Spring Security 6.4.11+ / 6.5.5+ fixes generic annotation resolution
// (pull in Spring Framework 6.2.11+ / 6.1.23+ / 5.3.45+ for CVE-2025-41249)
```

**Source:**
- https://spring.io/security/cve-2025-41248
- https://nvd.nist.gov/vuln/detail/cve-2025-41248
- https://www.loginsoft.com/post/cve-2025-41248-spring-security-authorization-bypass-in-method-security-annotations-on-parameterized-types

---

## 2. Filter Chain Ordering — Critical Misconfiguration

### The Problem

Spring Security's filter chain must be ordered correctly. A misordered chain can bypass ALL security.

**Vulnerable Code:**
```java
// 💀 VULNERABLE — Disordered filter chain bypasses security
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain publicFilterChain(HttpSecurity http) throws Exception {
        http
            .securityMatcher("/api/public/**")  // 💀 Public routes matched first
            .authorizeHttpRequests(auth -> auth.anyRequest().permitAll());
        return http.build();
    }

    @Bean
    public SecurityFilterChain mainFilterChain(HttpSecurity http) throws Exception {
        http
            .securityMatcher("/api/**")
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/api/admin/**").hasRole("ADMIN")
                .anyRequest().authenticated()
            )
            .oauth2Login(Customizer.withDefaults());  // 💀 OAuth2 config on wrong chain
        return http.build();
    }
}
// 💀 Problem: /api/public/../admin/delete may route to wrong chain
```

**Secure Code:**
```java
// ✅ SECURE — Correct filter chain ordering
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    // Most specific routes FIRST
    @Bean
    @Order(1)
    public SecurityFilterChain adminFilterChain(HttpSecurity http) throws Exception {
        http
            .securityMatcher("/api/admin/**")
            .authorizeHttpRequests(auth -> auth.anyRequest().hasRole("ADMIN"))
            .httpBasic(Customizer.withDefaults());
        return http.build();
    }

    // Then public routes
    @Bean
    @Order(2) 
    public SecurityFilterChain publicFilterChain(HttpSecurity http) throws Exception {
        http
            .securityMatcher("/api/public/**")
            .authorizeHttpRequests(auth -> auth.anyRequest().permitAll());
        return http.build();
    }

    // Default catch-all LAST
    @Bean
    @Order(3)
    public SecurityFilterChain defaultFilterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/api/auth/**").authenticated()
                .anyRequest().authenticated()
            )
            .oauth2Login(Customizer.withDefaults());
        return http.build();
    }
}
```

---

## 3. CORS Configuration Pitfalls

### CVE Pattern: All Origins + Credentials

**Vulnerable Code:**
```java
// 💀 VULNERABLE — Wide-open CORS configuration
@Configuration
public class CorsConfig {

    @Bean
    public WebMvcConfigurer corsConfigurer() {
        return new WebMvcConfigurer() {
            @Override
            public void addCorsMappings(CorsRegistry registry) {
                registry.addMapping("/**")
                    .allowedOrigins("*")        // 💀 Any origin
                    .allowedMethods("*")        // 💀 Any method
                    .allowedHeaders("*")        // 💀 Any header
                    .allowCredentials(true);    // 💀 Credentials with wildcard = ILLEGAL
                    // ⚠️ Browsers will refuse this configuration!
                    // But developers often miss this interaction
            }
        };
    }
}
```

**Secure Code:**
```java
// ✅ SECURE — Restricted CORS with Spring Security integration
@Configuration
public class CorsConfig {

    @Bean
    public WebMvcConfigurer corsConfigurer() {
        return new WebMvcConfigurer() {
            @Override
            public void addCorsMappings(CorsRegistry registry) {
                registry.addMapping("/api/**")
                    .allowedOrigins("https://app.example.com")
                    .allowedMethods("GET", "POST", "PUT", "DELETE")
                    .allowedHeaders("Authorization", "Content-Type")
                    .exposedHeaders("X-Request-Id")
                    .allowCredentials(false)       // ✅ No credentials with specific origins
                    .maxAge(3600);
            }
        };
    }
}
```

### CORS in Spring Security vs Spring MVC

**Vulnerable Code:**
```java
// 💀 VULNERABLE — CORS configured in MVC but overridden by Spring Security
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .cors(cors -> cors.disable())  // 💀 Disables CORS from MVC config!
            .authorizeHttpRequests(auth -> auth.anyRequest().authenticated());
        return http.build();
    }
}
```

**Secure Code:**
```java
// ✅ SECURE — CORS configured in Spring Security filter chain
@Bean
public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    http
        .cors(cors -> cors.configurationSource(corsConfigurationSource()))
        .authorizeHttpRequests(auth -> auth.anyRequest().authenticated());
    return http.build();
}

@Bean
public CorsConfigurationSource corsConfigurationSource() {
    CorsConfiguration config = new CorsConfiguration();
    config.setAllowedOrigins(Arrays.asList("https://app.example.com"));
    config.setAllowedMethods(Arrays.asList("GET", "POST"));
    config.setAllowedHeaders(Arrays.asList("Authorization"));
    config.setAllowCredentials(false);
    
    UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
    source.registerCorsConfiguration("/api/**", config);
    return source;
}
```

---

## 4. OAuth2 Pitfalls

### Insecure Redirect URI Validation

**Vulnerable Code:**
```java
// 💀 VULNERABLE — Loose redirect URI matching
@Configuration
@EnableWebSecurity
public class OAuth2Config {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .oauth2Login(oauth2 -> oauth2
                .successHandler((request, response, auth) -> {
                    // 💀 Allows redirect to attacker-controlled URL
                    String redirectUrl = request.getParameter("redirect_uri");
                    response.sendRedirect(redirectUrl);  // Open redirect!
                })
            );
        return http.build();
    }
}
```

**Secure Code:**
```java
// ✅ SECURE — Strict redirect validation
@Bean
public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    http
        .oauth2Login(oauth2 -> oauth2
            .successHandler(oAuth2SuccessHandler())
        );
    return http.build();
}

@Component
public class OAuth2SuccessHandler extends SimpleUrlAuthenticationSuccessHandler {
    
    private static final List<String> ALLOWED_REDIRECTS = Arrays.asList(
        "https://app.example.com/dashboard",
        "https://app.example.com/profile"
    );

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication) throws IOException {
        String targetUrl = request.getParameter("redirect_uri");
        
        if (targetUrl == null || !ALLOWED_REDIRECTS.contains(targetUrl)) {
            targetUrl = getDefaultTargetUrl();
        }
        
        getRedirectStrategy().sendRedirect(request, response, targetUrl);
    }
}
```

### Client Secret Exposure

**Vulnerable Code:**
```yaml
# application.yml — 💀 Hardcoded OAuth2 client secret
spring:
  security:
    oauth2:
      client:
        registration:
          google:
            client-id: "123456789.apps.googleusercontent.com"
            client-secret: "GOCSPX-xxxxxxxxxxxxxxxxxxxxxx"  # 💀 Hardcoded!
```

**Secure Code:**
```yaml
# application.yml — ✅ Use environment variables or secrets manager
spring:
  security:
    oauth2:
      client:
        registration:
          google:
            client-id: ${OAUTH2_GOOGLE_CLIENT_ID}
            client-secret: ${OAUTH2_GOOGLE_CLIENT_SECRET}
```

```bash
# Or use Spring Cloud Config / Vault
# export OAUTH2_GOOGLE_CLIENT_SECRET=$(vault read ...)
```

---

## 5. CSRF Configuration

**Vulnerable Code:**
```java
// 💀 VULNERABLE — CSRF completely disabled
@Bean
public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    http
        .csrf(csrf -> csrf.disable())  // 💀 Disables CSRF globally
        .authorizeHttpRequests(auth -> auth.anyRequest().authenticated());
    return http.build();
}
```

**Secure Code:**
```java
// ✅ SECURE — CSRF enabled (default), or selectively disabled per endpoint
@Bean
public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    http
        .csrf(csrf -> csrf
            .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
            .csrfTokenRequestHandler(new CsrfTokenRequestAttributeHandler())
            .ignoringRequestMatchers("/api/webhook/**")  // ✅ Only for webhooks
        )
        .authorizeHttpRequests(auth -> auth.anyRequest().authenticated());
    return http.build();
}

// ✅ For stateless APIs (JWT), keep CSRF disabled but ensure token security
@Bean
public SecurityFilterChain apiFilterChain(HttpSecurity http) throws Exception {
    http
        .securityMatcher("/api/**")
        .csrf(csrf -> csrf.disable())  // Acceptable for stateless JWT APIs
        .sessionManagement(sm -> sm.sessionCreationPolicy(STATELESS))
        .oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()));
    return http.build();
}
```

---

## 6. Session Fixation

**Vulnerable Code:**
```java
// 💀 VULNERABLE — No session fixation protection
@Bean
public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    http
        .sessionManagement(sm -> sm
            .sessionFixation().none()  // 💀 No protection
        );
    return http.build();
}
```

**Secure Code:**
```java
// ✅ SECURE — Session fixation protection
@Bean
public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    http
        .sessionManagement(sm -> sm
            .sessionFixation().migrateSession()  // ✅ Create new session after auth
            .maximumSessions(1)                   // ✅ Limit concurrent sessions
            .maxSessionsPreventsLogin(false)      // ✅ Force logout oldest session
        );
    return http.build();
}
```

---

## 7. Security Headers

**Vulnerable Code:**
```java
// 💀 VULNERABLE — Headers not configured
@Bean
public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    http
        .headers(headers -> headers.disable())  // 💀 No security headers
        .authorizeHttpRequests(auth -> auth.anyRequest().authenticated());
    return http.build();
}
```

**Secure Code:**
```java
// ✅ SECURE — Comprehensive security headers
@Bean
public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    http
        .headers(headers -> headers
            .contentSecurityPolicy(csp -> csp
                .policyDirectives("default-src 'self'; script-src 'self'")
            )
            .frameOptions(fo -> fo.deny())
            .contentTypeOptions(cto -> cto.disable())  // Already default: nosniff
            .hsts(hsts -> hsts
                .includeSubDomains(true)
                .maxAgeInSeconds(31536000)
                .preload(true)
            )
            .cacheControl(cache -> cache.disable())    // Already default: no-cache
            .referrerPolicy(ref -> ref
                .policy(ReferrerPolicyHeaderWriter.ReferrerPolicy.STRICT_ORIGIN_WHEN_CROSS_ORIGIN)
            )
        );
    return http.build();
}
```

---

## 8. CVE Roundup

| CVE | CVSS | Affected | Type | Fixed In |
|-----|------|----------|------|----------|
| CVE-2025-41248 | 7.5 | Spring Security 6.4.0–6.4.10, 6.5.0–6.5.4 | Method-security annotation bypass on parameterized types | 6.4.11, 6.5.5 |
| CVE-2025-41249 | 7.5 | Spring Framework 5.3.0–5.3.44, 6.1.0–6.1.22, 6.2.0–6.2.10 | Annotation detection bypass on generic supertypes (enables the above) | 5.3.45, 6.1.23, 6.2.11 |
| CVE-2024-38819 | 7.5 | Spring Framework 5.3.0–5.3.40, 6.0.0–6.0.24, 6.1.0–6.1.13 | Path traversal in WebMvc.fn / WebFlux.fn static resources (CWE-22) | 5.3.41, 6.0.25, 6.1.14 |
| CVE-2024-22262 | 8.1 | Spring Framework 5.3.0–5.3.33, 6.0.0–6.0.18, 6.1.0–6.1.5 | Open redirect / SSRF via UriComponentsBuilder | 5.3.34, 6.0.19, 6.1.6 |

---

## 9. Version Recommendations

| Framework | Version | Status |
|-----------|---------|--------|
| Spring Boot | 3.4.x | ✅ Latest stable |
| Spring Security | 6.4.11+ / 6.5.5+ | ✅ Patched against CVE-2025-41248 |
| Spring Framework | 6.2.11+ / 6.1.23+ / 5.3.45+ | ✅ Patched against CVE-2025-41249, CVE-2024-38819, CVE-2024-22262 |
| Spring Cloud (OAuth2) | 2024.0.x | ✅ Latest |

---

## 10. Common AI-Produced Misconfigurations

1. **`@PreAuthorize` on generic base classes** — Annotation bypass on parameterized types (CVE-2025-41248)
2. **`cors().disable()` in Spring Security** — Overriding MVC CORS configuration
3. **`*` allowedOrigins with `allowCredentials(true)`** — Illegal CORS combination
4. **Filter chains without `@Order`** — Non-deterministic chain ordering
5. **`csrf().disable()` on non-API apps** — Disabling CSRF for stateful apps
6. **`sessionFixation().none()`** — Missing session fixation protection
7. **OAuth2 with open redirect** — Unsafe redirect_uri handling
8. **Client secret hardcoded** — OAuth2 credentials in source code
9. **`headers().disable()`** — Missing all security headers
10. **`permitAll()` before authentication** — Public access to unauthenticated routes

---

## Verification / Source URLs

- Spring Security CVE-2025-41248: https://spring.io/security/cve-2025-41248
- NVD CVE-2025-41248: https://nvd.nist.gov/vuln/detail/cve-2025-41248
- Spring Security Architecture: https://docs.spring.io/spring-security/reference/servlet/architecture.html
- Spring Security CORS: https://docs.spring.io/spring-security/reference/servlet/integrations/cors.html
- Spring Security OAuth2: https://docs.spring.io/spring-security/reference/servlet/oauth2/index.html
- OWASP Spring Security Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Spring_Security_Cheat_Sheet.html
- Spring Security CSRF: https://docs.spring.io/spring-security/reference/servlet/exploits/csrf.html
