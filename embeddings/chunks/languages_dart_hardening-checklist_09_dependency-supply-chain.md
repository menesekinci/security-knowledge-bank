---
source: "languages/dart/hardening-checklist.md"
title: "🛡️ Flutter / Dart Hardening Checklist"
heading: "Dependency Supply Chain"
category: "checklist"
language: "common"
severity: "critical"
tags: [build, checklist, compilation, credentials, input, local, network, secrets, security, storage]
chunk: 9/11
---

## Dependency Supply Chain

- [ ] **🟠 Pin dependency versions and commit `pubspec.lock`**
  - Audit regularly: `dart pub outdated` and `dart pub deps`
  - Check for known vulnerabilities

- [ ] **🟠 Review package permissions and health before adding dependencies**
  - Check `pub.dev` for package health, likes, popularity, and recent updates
  - Prefer packages with 100+ likes, maintained within the last 6 months
  - Avoid packages with excessive native permissions

- [ ] **🔵 Use automated dependency scanning in CI**
  - Integrate Dependabot, Snyk, GitHub Advisory Database, or Socket.dev

---