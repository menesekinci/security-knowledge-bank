---
source: "common/websocket.md"
title: "WebSocket Security Vulnerabilities"
heading: "Real-World CVEs / References"
category: "common-vuln"
language: "common"
severity: "high"
tags: [checklist, code, common-vuln, explanation, prevention, secure, vulnerability, vulnerable]
chunk: 7/8
---

## Real-World CVEs / References

| Reference | Relevance |
|-----------|-----------|
| [CWE-1385](https://cwe.mitre.org/data/definitions/1385.html) | Missing Origin Validation in WebSockets (CSWSH class) |
| [CWE-352](https://cwe.mitre.org/data/definitions/352.html) | Cross-Site Request Forgery — related browser-driven abuse of cookie auth |
| [OWASP HTML5 Security Cheat Sheet — WebSockets](https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html#websockets) | Origin checks, authentication, input validation guidance |
| [RFC 6455](https://datatracker.ietf.org/doc/html/rfc6455) | WebSocket protocol (Origin header semantics) |
| [PortSwigger — Cross-site WebSocket hijacking](https://portswigger.net/web-security/websockets/cross-site-websocket-hijacking) | Practical CSWSH methodology |
| Memory-safety adjacent stacks (native WS libs) | Historical issues such as [CVE-2014-0160 Heartbleed](https://nvd.nist.gov/vuln/detail/CVE-2014-0160) show why TLS/memory safety of the transport stack still matters for any long-lived channel |

CSWSH is primarily a **logic/design** flaw rather than a single CVE ID; treat CWE-1385 and OWASP WebSocket guidance as the primary mapping, and track library-specific CVEs in your dependency scanner for `ws`, `socket.io`, nginx, and TLS stacks.

---