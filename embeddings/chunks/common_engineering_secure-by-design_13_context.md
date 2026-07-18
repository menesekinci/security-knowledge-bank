---
source: "common/engineering/secure-by-design.md"
title: "Secure by Design"
heading: "Context"
category: "common-vuln"
language: "common"
severity: "medium"
tags: [architecture, common-vuln, decision, requirements, secure, security, status, table, what]
chunk: 13/25
---

## Context
The new customer-facing API needs authentication. We evaluated session cookies
vs token-based auth. The threat model identified spoofing (STRIDE-S) as the
primary concern: an attacker who steals a session cookie can impersonate any user.