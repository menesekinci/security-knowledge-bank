---
source: "languages/java/dependency-safety.md"
title: "Dependency Safety — Maven/Gradle Supply Chain"
heading: "AI-Generated Vulnerability: No Version Pinning"
category: "language-vuln"
language: "java"
severity: "medium"
tags: [ai-generated, java, language-vuln, overview, unique, vulnerability]
chunk: 4/13
---

## AI-Generated Vulnerability: No Version Pinning

```xml
<!-- AI-GENERATED pom.xml — uses version ranges (DANGEROUS!) -->
<dependency>
    <groupId>com.example</groupId>
    <artifactId>vulnerable-library</artifactId>
    <version>[1.0,)</version>  <!-- BUG: Resolves to LATEST version -->
</dependency>
```

**Problems with version ranges**:
- `[1.0,)` = any version >= 1.0, may resolve to a backdoored version
- `(,1.0]` = any version ≤ 1.0, may include vulnerable versions
- `[1.0,2.0)` = within range, but Maven may pick a compromised subversion
- Maven's version range resolution is non-deterministic across mirrors

**Secure Fix**: Pin to exact versions.
```xml
<dependency>
    <groupId>com.example</groupId>
    <artifactId>safe-library</artifactId>
    <version>1.2.5</version>  <!-- Exact version -->
</dependency>
```