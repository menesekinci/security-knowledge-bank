---
source: "languages/java/spring-security-deep.md"
title: "Spring Security Deep Dive"
category: "language-vuln"
language: "java"
chunk: 7
total_chunks: 13
heading: "5. CSRF Configuration"
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