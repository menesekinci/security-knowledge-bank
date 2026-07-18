---
source: "languages/java/dependency-safety.md"
title: "Dependency Safety — Maven/Gradle Supply Chain"
category: "language-vuln"
language: "java"
chunk: 3
total_chunks: 13
heading: "The Unique Risk Profile of Java Dependencies"
---

## The Unique Risk Profile of Java Dependencies

| Factor | Impact |
|---|---|
| **Age of ecosystem** | Maven Central artifacts from 2000s are still used; some maintainers have passed away |
| **Transitive depth** | A Spring Boot app can have 200+ transitive dependencies |
| **Gradle vs. Maven** | Different resolution strategies, version conflict handling |
| **Binary-only artifacts** | Many JARs have no source code available for review |
| **Multi-module projects** | Complex dependency graphs across modules |
| **System dependency scope** | JRE/JDK itself is a dependency (Oracle JRE vs OpenJDK) |