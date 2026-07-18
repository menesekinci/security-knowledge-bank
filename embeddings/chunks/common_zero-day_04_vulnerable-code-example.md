---
source: "common/zero-day.md"
title: "Zero-Day Vulnerabilities (0-day) and Patch Lag (n-day)"
heading: "Vulnerable Code Example (realistic)"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [checklist, code, common-vuln, explanation, prevention, secure, vulnerability, vulnerable]
chunk: 4/8
---

## Vulnerable Code Example (realistic)

Illustrative **n-day / patch-lag patterns** (not exploit PoCs) — patterns AI frequently emits:

### 1) Pinned known-vulnerable dependency (conceptual)

```xml
<!-- pom.xml — AI regenerated from an old tutorial -->
<dependency>
  <groupId>org.apache.logging.log4j</groupId>
  <artifactId>log4j-core</artifactId>
  <!-- 🔴 Version known-vulnerable during Log4Shell era; still appears in stale examples -->
  <version>2.14.1</version>
</dependency>
```

### 2) “It works” suppression of SCA

```yaml
# .github/workflows/ci.yml — AI "fixed" failing pipeline
- name: Audit
  run: npm audit
  continue-on-error: true   # 🔴 n-day CVEs never block merge
```

### 3) Unpinned base image + no rebuild policy

```dockerfile
FROM node:16   # 🔴 EOL base; AI defaults from old docs
COPY . .
RUN npm install   # no npm ci, no lockfile verification
CMD ["node", "server.js"]
```

### 4) Incomplete “mitigation” comment without actual upgrade

```java
// "Mitigated Log4Shell by not logging user input"  — 🔴 incomplete; JNDI still reachable via other paths
log.info("User action");
```

These examples show **process and supply-chain** failures that keep n-day risk alive; they are not attack recipes.

---