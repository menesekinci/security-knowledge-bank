---
source: "languages/java/spring-boot-actuator.md"
title: "Spring Boot Actuator Security Deep Dive"
heading: "4. Custom Endpoints — Security Bypass"
category: "language-vuln"
language: "java"
severity: "medium"
tags: [custom, cve-2025-48927, endpoint, endpoints, full, heap, java, language-vuln, overview]
chunk: 6/13
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