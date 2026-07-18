---
source: "languages/java/dependency-safety.md"
title: "Dependency Safety — Maven/Gradle Supply Chain"
category: "language-vuln"
language: "java"
chunk: 8
total_chunks: 13
heading: "Gradle-Specific Issues"
---

## Gradle-Specific Issues

### Dynamic Versions in Gradle

```groovy
// AI-GENERATED build.gradle — dynamic versions
dependencies {
    implementation 'com.example:library:1.+'   // BUG: Picks latest patch
    implementation 'com.example:another:latest.integration'  // BUG: Always latest!
    implementation 'com.example:newest:+'  // BUG: Any version
}
```

### Gradle Module Metadata Attack

Gradle's module metadata (.module files) can replace transitive dependencies — a technique used in dependency confusion attacks. AI-generated Gradle code rarely pins these.