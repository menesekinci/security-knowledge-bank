---
source: "common/zero-day.md"
title: "Zero-Day Vulnerabilities (0-day) and Patch Lag (n-day)"
heading: "How AI / Vibe Coding Generates This"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [checklist, code, common-vuln, explanation, prevention, secure, vulnerability, vulnerable]
chunk: 3/8
---

## How AI / Vibe Coding Generates This

Vibe coding increases **n-day exposure** and can accidentally reintroduce **known** vulnerable patterns:

- Scaffolding with `npm create` / `pip install` of packages pinned to old majors from blog posts.
- AI copies Log4j-era Java logging or JNDI usage from old Stack Overflow answers still in the corpus.
- Generated Dockerfiles based on `ubuntu:latest` or unpinned base images that lag behind security updates.
- “Upgrade later” comments left in AI-generated TODOs that never become tickets.
- Agents that “solve the error” by **downgrading** a package to an older version that compiles — often reintroducing fixed CVEs.
- Auto-generated SBOM-less monorepos where transitive deps are invisible to developers.
- Security “fixes” that only rename variables or add comments claiming a CVE is addressed.
- Using AI to write WAF rules or detections from incomplete public writeups, creating a false sense of safety while the root package remains vulnerable.

For true 0-days, AI does not “create” vendor 0-days, but AI-assisted development can:

- Increase attack surface (more code, more deps, more exposed endpoints) faster than security review scales.
- Normalize insecure defaults that become the next class of 0-day hunting ground (e.g. novel deserialization sinks, new template engines).

---