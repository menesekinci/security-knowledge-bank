---
source: "languages/java/spring-boot-actuator.md"
title: "Spring Boot Actuator Security Deep Dive"
category: "language-vuln"
language: "java"
chunk: 11
total_chunks: 13
heading: "9. Common AI-Produced Misconfigurations"
---

## 9. Common AI-Produced Misconfigurations

1. **`management.endpoints.web.exposure.include: "*"`** — Most common wildcard exposure
2. **No authentication on actuator endpoints** — Open to anyone who finds them
3. **Heap dump left enabled** — Full JVM memory downloadable (CVE-2025-48927)
4. **`/env` endpoint exposing credentials** — Database passwords, API keys
5. **`/configprops` showing internal URLs and secrets**
6. **Custom endpoints without authorization checks**
7. **Actuator on default port (8080) with no IP restriction**
8. **`show-details: ALWAYS` on health endpoint** — Database status, disk space
9. **Loggers endpoint writable** — Allows runtime log level changes
10. **Spring Boot 1.x actuator** — `/dump` and `/trace` had no auth by default

---