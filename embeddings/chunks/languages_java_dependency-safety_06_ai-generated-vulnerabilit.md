---
source: "languages/java/dependency-safety.md"
title: "Dependency Safety — Maven/Gradle Supply Chain"
heading: "AI-Generated Vulnerability: Using Deprecated/Vulnerable Logging Libraries"
category: "language-vuln"
language: "java"
severity: "medium"
tags: [ai-generated, java, language-vuln, overview, unique, vulnerability]
chunk: 6/13
---

## AI-Generated Vulnerability: Using Deprecated/Vulnerable Logging Libraries

```xml
<!-- AI-GENERATED — uses Log4j 2.14.1 (PRE-Log4Shell!) -->
<dependency>
    <groupId>org.apache.logging.log4j</groupId>
    <artifactId>log4j-core</artifactId>
    <version>2.14.1</version>  <!-- CVE-2021-44228 (Log4Shell) -->
</dependency>
```