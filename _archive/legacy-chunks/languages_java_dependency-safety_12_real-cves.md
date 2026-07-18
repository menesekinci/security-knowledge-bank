---
source: "languages/java/dependency-safety.md"
title: "Dependency Safety — Maven/Gradle Supply Chain"
category: "language-vuln"
language: "java"
chunk: 12
total_chunks: 13
heading: "Real CVEs"
---

## Real CVEs

- **CVE-2021-44228 (Log4Shell)**: CVSS 10.0 — The most impactful supply chain vulnerability. Log4j 2.x was a transitive dependency in thousands of Java applications. Organizations that didn't track transitive deps were vulnerable without knowing it.
- **CVE-2022-22965 (Spring4Shell)**: CVSS 9.8 — Spring Framework vulnerability affecting all applications using Spring MVC or WebFlux with JDK 9+. Required urgent patching across the entire Java ecosystem.
- **CVE-2023-46604 (Apache Struts 2)**: CVSS 9.8 — The latest Struts 2 OGNL vulnerability. Struts has had over 20 critical CVEs since 2017, yet many enterprise applications still run vulnerable versions.
- **CVE-2024-38808 (Spring SpEL)**: CVSS 8.1 — Spring Framework's `spring-expression` module vulnerability — a transitive dependency of virtually every Spring Boot application.