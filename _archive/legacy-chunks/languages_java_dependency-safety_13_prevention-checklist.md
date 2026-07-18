---
source: "languages/java/dependency-safety.md"
title: "Dependency Safety — Maven/Gradle Supply Chain"
category: "language-vuln"
language: "java"
chunk: 13
total_chunks: 13
heading: "Prevention Checklist"
---

## Prevention Checklist

1. **Pin exact versions** — Never use version ranges or `+` in Gradle.
2. **Use OWASP Dependency-Check in CI** — Fail the build on CVSS 7+ vulnerabilities.
3. **Review all transitive dependencies** — `mvn dependency:tree` or `gradle dependencies`.
4. **Ban known-problematic libraries** — Commons Collections 3.x, Log4j < 2.17, older Struts.
5. **Use Maven Enforcer** — Enforce no Snapshots, dependency convergence, banned deps.
6. **Use a private artifact repository** — Nexus, Artifactory control which artifacts enter your build.
7. **Scan for dependency confusion** — Ensure internal artifact names are reserved on Maven Central.
8. **Update dependencies regularly** — Don't accumulate technical debt in vulnerable libs.
9. **Use `mvn verify` and `gradle build` with security scanning** — Every build.
10. **Generate SBOM (Software Bill of Materials)** — `mvn cyclonedx:makeBom` or `gradle cyclonedxBom`.