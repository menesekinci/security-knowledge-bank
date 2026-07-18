---
source: "common/engineering/secure-by-design.md"
title: "Secure by Design"
heading: "Decision"
category: "common-vuln"
language: "common"
severity: "medium"
tags: [architecture, common-vuln, decision, requirements, secure, security, status, table, what]
chunk: 14/25
---

## Decision
Use OAuth 2.0 with JWT access tokens. Access tokens expire in 15 minutes;
refresh tokens expire in 7 days and are stored in an HttpOnly, Secure, SameSite=Strict cookie.