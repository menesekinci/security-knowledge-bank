---
source: "common/oauth2-security.md"
title: "OAuth 2.0 Security — Implicit Grant, Redirect URI, CSRF, PKCE, Token Leakage"
heading: "Why Vibe Coding Makes This Worse"
category: "common-vuln"
language: "common"
severity: "medium"
tags: [checklist, common-vuln, cves, major, oauth, prevention, real-world, vibe, what]
chunk: 3/8
---

## Why Vibe Coding Makes This Worse

- **AI assumes OAuth 2.0 is "secure by default"** — It's not. The framework is a toolbox, not a security solution.
- **AI often implements Implicit Grant** — Many AI-generated tutorials still use the deprecated implicit flow.
- **AI skips `state` parameter** — The most common CSRF prevention mechanism is seen as "optional complexity."
- **AI generates loose redirect URI validation** — Pattern matching with `startsWith()` instead of exact match.
- **AI misunderstands PKCE** — Implements the flow without validating the code verifier.

---