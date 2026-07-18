---
source: "common/websocket.md"
title: "WebSocket Security Vulnerabilities"
heading: "intro"
category: "common-vuln"
language: "common"
severity: "high"
tags: [checklist, code, common-vuln, explanation, prevention, secure, vulnerability, vulnerable]
chunk: 1/8
---

# WebSocket Security Vulnerabilities

> **Severity:** High (CSWSH / auth bypass often Critical)  
> **CWE:** CWE-1385 (Missing Origin Validation in WebSockets), CWE-346 (Origin Validation Error), CWE-352 (CSRF), CWE-319 (Cleartext Transmission)  
> **AI Generation Risk:** High — AI chat/live-update samples almost never implement Origin checks, token binding, or message schema validation

---