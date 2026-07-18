---
source: "languages/java/spring-security-deep.md"
title: "Spring Security Deep Dive"
category: "language-vuln"
language: "java"
chunk: 9
total_chunks: 13
heading: "7. Security Headers"
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