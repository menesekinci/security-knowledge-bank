---
source: "common/websocket.md"
title: "WebSocket Security Vulnerabilities"
heading: "Vibe-Coding Red Flags"
category: "common-vuln"
language: "common"
severity: "high"
tags: [checklist, code, common-vuln, explanation, prevention, secure, vulnerability, vulnerable]
chunk: 8/8
---

## Vibe-Coding Red Flags

| Red flag in AI output | Why it matters |
|----------------------|----------------|
| `new WebSocket.Server({ server })` with no `verifyClient` | Open to any Origin + cookie ride |
| “Auth is handled by express-session” only | Classic CSWSH setup |
| `ws://` in React/Vue example “for simplicity” | Ships cleartext if env not overridden |
| `?token=` on the WebSocket URL as the only auth | Token leakage via logs/Referer |
| `JSON.parse(message)` with no size/schema checks | Parser DoS + injection gadgets |
| Client decides `role: 'admin'` in first message | Trivial privilege escalation |
| Infinite reconnect without backoff or auth refresh | Stale sessions, thundering herd |
| No tests for foreign Origin handshake | Regression will reintroduce CSWSH |
| Socket.IO CORS `origin: '*'` with credentials | Equivalent to disabling origin trust |
| Shared global socket across tabs without isolation | Confused deputy / data bleed between accounts |

**Rule of thumb for review:** If the PR adds WebSockets and the diff does not mention Origin, tickets/tokens, max payload, and rate limits, treat it as insecure by default until proven otherwise.

---

*KB level: L1 common · Protocol: WebSocket · Primary abuse: CSWSH (CWE-1385) · Pair with: CORS, CSRF, auth session design*