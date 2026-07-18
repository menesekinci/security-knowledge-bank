---
source: "languages/java/jwt-misuse.md"
title: "JWT Misuse — JJWT, Nimbus JOSE, and Common Pitfalls"
heading: "AI-Generated Vulnerability: Using JWT for Session Management"
category: "language-vuln"
language: "java"
severity: "medium"
tags: [ai-generated, algorithm, confusion, java, language-vuln, overview, vulnerability]
chunk: 7/10
---

## AI-Generated Vulnerability: Using JWT for Session Management

JWT is frequently recommended by AI as a "better session token" — but this is often the wrong approach:

```java
// AI-GENERATED — uses JWT as long-lived session token
// Problems: no way to revoke, can't invalidate on logout, token stolen = permanent access
```

**Best practice**: Use opaque session identifiers (server-side sessions) for web apps. Reserve JWT for API-to-API authentication with short expiration and refresh token rotation.