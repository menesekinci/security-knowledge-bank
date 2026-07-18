---
source: "languages/java/spring-security-deep.md"
title: "Spring Security Deep Dive"
heading: "2. Filter Chain Ordering — Critical Misconfiguration"
category: "language-vuln"
language: "java"
severity: "high"
tags: [chain, configuration, cors, cve-2025-41248, filter, java, language-vuln, oauth2, overview, pitfalls]
chunk: 4/13
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