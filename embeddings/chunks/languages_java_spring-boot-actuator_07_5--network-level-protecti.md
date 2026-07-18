---
source: "languages/java/spring-boot-actuator.md"
title: "Spring Boot Actuator Security Deep Dive"
heading: "5. Network-Level Protection"
category: "language-vuln"
language: "java"
severity: "medium"
tags: [custom, cve-2025-48927, endpoint, endpoints, full, heap, java, language-vuln, overview]
chunk: 7/13
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