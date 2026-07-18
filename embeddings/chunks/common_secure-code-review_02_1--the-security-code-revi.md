---
source: "common/secure-code-review.md"
title: "🔍 Secure Code Review Checklist"
heading: "1. The Security Code Review Process"
category: "common-vuln"
language: "common"
severity: "medium"
tags: [ai-generated, automated, common-vuln, flags, language-specific, review, reviewing, security]
chunk: 2/8
---

## 1. The Security Code Review Process

```
┌──────────────────────────────────────────────────────────┐
│                SECURE CODE REVIEW FLOW                     │
├──────────────────────────────────────────────────────────┤
│                                                           │
│  PR CREATED                                               │
│     │                                                     │
│  1. AUTOMATED GATES                                       │
│     ├─ SAST (Semgrep, CodeQL, Brakeman, etc.)             │
│     ├─ Secret scan (Gitleaks, truffleHog)                 │
│     ├─ Dependency scan (Trivy, npm audit)                 │
│     └─ Linting + formatting                               │
│     │                                                     │
│  2. MANUAL REVIEW                                         │
│     ├─ Check the CHANGES, not the whole file              │
│     ├─ Focus on HIGH RISK areas                           │
│     │   ├─ Auth / authorization                           │
│     │   ├─ Data validation / sanitization                 │
│     │   ├─ Crypto / secrets                               │
│     │   ├─ Serialization / deserialization                │
│     │   ├─ SQL / query building                           │
│     │   ├─ File I/O / path handling                       │
│     │   └─ External integrations                          │
│     └─ Use checklist below                                │
│     │                                                     │
│  3. DECISION                                              │
│     ├─ Approve (no security concerns)                     │
│     ├─ Changes requested (fix security issues)            │
│     └─ Block (critical vulnerability)                     │
│                                                           │
└──────────────────────────────────────────────────────────┘
```

---