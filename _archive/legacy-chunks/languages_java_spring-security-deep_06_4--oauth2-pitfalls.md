---
source: "languages/java/spring-security-deep.md"
title: "Spring Security Deep Dive"
category: "language-vuln"
language: "java"
chunk: 6
total_chunks: 13
heading: "4. OAuth2 Pitfalls"
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