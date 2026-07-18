---
source: "languages/java/spring-security-deep.md"
title: "Spring Security Deep Dive"
category: "language-vuln"
language: "java"
chunk: 8
total_chunks: 13
heading: "6. Session Fixation"
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