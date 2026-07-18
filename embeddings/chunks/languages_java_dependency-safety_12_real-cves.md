---
source: "languages/java/dependency-safety.md"
title: "Dependency Safety — Maven/Gradle Supply Chain"
heading: "Real CVEs"
category: "language-vuln"
language: "java"
severity: "medium"
tags: [ai-generated, java, language-vuln, overview, unique, vulnerability]
chunk: 12/13
---

## Real CVEs

- **CVE-2021-44228 (Log4Shell)**: CVSS 10.0 — The most impactful supply chain vulnerability. Log4j 2.x was a transitive dependency in thousands of Java applications. Organizations that didn't track transitive deps were vulnerable without knowing it.
- **CVE-2022-22965 (Spring4Shell)**: CVSS 9.8 — Spring Framework vulnerability affecting all applications using Spring MVC or WebFlux with JDK 9+. Required urgent patching across the entire Java ecosystem.
- **CVE-2023-46604 (Apache ActiveMQ)**: CVSS 9.8 — RCE in the Java OpenWire protocol marshaller: a crafted serialized class type lets an unauthenticated attacker instantiate arbitrary classpath objects and run shell commands. Widely exploited in the wild against outdated ActiveMQ deployments.
- **CVE-2024-38808 (Spring SpEL)**: CVSS 4.3 — a crafted SpEL expression triggers a **denial of service** in Spring Framework's `spring-expression` module — a transitive dependency of virtually every Spring Boot application.