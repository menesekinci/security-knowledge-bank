---
source: "languages/java/dependency-safety.md"
title: "Dependency Safety — Maven/Gradle Supply Chain"
category: "language-vuln"
language: "java"
chunk: 9
total_chunks: 13
heading: "The Transitive Dependency Bomb"
---

## The Transitive Dependency Bomb

```xml
<!-- AI adds one dependency, which pulls in 50 more -->
<dependency>
    <groupId>org.apache.commons</groupId>
    <artifactId>commons-collections4</artifactId>
    <version>4.4</version>
</dependency>
<!-- This pulls in: commons-collections4, commons-lang3, etc. -->
```

AI-generated code frequently adds entire framework starters when a single lightweight library would suffice:

```xml
<!-- AI adds the whole Spring Boot starter for one feature -->
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-web</artifactId>
</dependency>
<!-- Instead of a specific lightweight library -->
```