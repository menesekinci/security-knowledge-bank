---
source: "languages/java/dependency-safety.md"
title: "Dependency Safety — Maven/Gradle Supply Chain"
category: "language-vuln"
language: "java"
chunk: 5
total_chunks: 13
heading: "AI-Generated Vulnerability: Dependency Confusion"
---

## AI-Generated Vulnerability: Dependency Confusion

```xml
<!-- AI-GENERATED — uses a dependency name that exists internally AND externally -->
<dependency>
    <groupId>com.company</groupId>
    <artifactId>internal-auth-library</artifactId>
    <version>3.0.0</version>
</dependency>
```

**Risk**: If an attacker publishes `com.company:internal-auth-library:4.0.0` to Maven Central, and the build resolves external repositories before internal ones, the attacker's version is used.

**Fix**: Require internal repository for internal group IDs.
```xml
<repositories>
    <repository>
        <id>internal</id>
        <url>https://internal-nexus.company.com/repository/maven-releases/</url>
    </repository>
</repositories>

<!-- In settings.xml, force internal repos first -->
<pluginRepositories>
    <pluginRepository>
        <id>internal</id>
        <url>https://internal-nexus.company.com/repository/maven-releases/</url>
        <releases><enabled>true</enabled></releases>
        <snapshots><enabled>false</enabled></snapshots>
    </pluginRepository>
</pluginRepositories>
```