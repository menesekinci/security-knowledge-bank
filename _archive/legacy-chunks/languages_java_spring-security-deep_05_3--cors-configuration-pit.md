---
source: "languages/java/spring-security-deep.md"
title: "Spring Security Deep Dive"
category: "language-vuln"
language: "java"
chunk: 5
total_chunks: 13
heading: "3. CORS Configuration Pitfalls"
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