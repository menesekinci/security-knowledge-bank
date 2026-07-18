---
source: "common/websocket.md"
title: "WebSocket Security Vulnerabilities"
heading: "Prevention Checklist"
category: "common-vuln"
language: "common"
severity: "high"
tags: [checklist, code, common-vuln, explanation, prevention, secure, vulnerability, vulnerable]
chunk: 6/8
---

## Prevention Checklist

- [ ] Validate `Origin` (or `Sec-WebSocket-Origin`) against a strict allowlist on every handshake
- [ ] Do not rely on cookies alone; use short-lived, single-use tickets or first-message bearer tokens
- [ ] Enforce `wss://` in production; reject cleartext upgrades at the edge
- [ ] Set `maxPayload` / max frame size; reject oversized messages early
- [ ] Rate-limit messages and connections per identity and per IP
- [ ] Schema-validate every message; never trust client-supplied roles/types for privilege
- [ ] Re-check authz for sensitive actions; push logout/revoke to open sockets
- [ ] Idle timeout and max lifetime for connections
- [ ] Avoid putting long-lived JWTs in query strings (proxy logs)
- [ ] Security tests: automated CSWSH case from a foreign Origin; fuzz message parser
- [ ] Document allowlisted origins in config, not hard-coded secrets in client bundles
- [ ] Review CDN/load-balancer WebSocket settings (sticky sessions, timeout, header passthrough)

---