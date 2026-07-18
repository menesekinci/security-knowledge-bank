---
source: "languages/java/dependency-safety.md"
title: "Dependency Safety — Maven/Gradle Supply Chain"
heading: "AI-Generated Vulnerability: Using Snapshots in Production"
category: "language-vuln"
language: "java"
severity: "medium"
tags: [ai-generated, java, language-vuln, overview, unique, vulnerability]
chunk: 7/13
---

## AI-Generated Vulnerability: Using Snapshots in Production

```xml
<!-- AI-GENERATED — uses snapshot in production -->
<dependency>
    <groupId>com.example</groupId>
    <artifactId>rapid-dev-framework</artifactId>
    <version>1.0-SNAPSHOT</version>  <!-- BUG: SNAPSHOT changes without warning! -->
</dependency>
```

**SNAPSHOT dependencies can change without a version bump** — a build that passed today may fail or behave differently tomorrow, including introducing vulnerabilities.