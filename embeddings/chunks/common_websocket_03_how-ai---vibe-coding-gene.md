---
source: "common/websocket.md"
title: "WebSocket Security Vulnerabilities"
heading: "How AI / Vibe Coding Generates This"
category: "common-vuln"
language: "common"
severity: "high"
tags: [checklist, code, common-vuln, explanation, prevention, secure, vulnerability, vulnerable]
chunk: 3/8
---

## How AI / Vibe Coding Generates This

AI coding assistants and “vibe coding” workflows produce insecure WebSocket stacks because tutorials and training snippets optimize for “it connects and echoes,” not for threat models:

- **Chat / multiplayer boilerplate** with `ws` or `socket.io` that accepts any Origin.
- **Cookie-only auth** copied from REST middleware without CSRF/Origin equivalents.
- **No per-message authorization** — once connected, any frame is trusted.
- **`ws://localhost` patterns** left in client bundles that ship to production.
- **Unbounded buffers** — `message` handlers that `JSON.parse` arbitrary size strings.
- **Socket.IO / SockJS defaults** without hardening flags documented in the same snippet.
- **Missing subprotocol negotiation** and no explicit close on policy violation.
- **AI “just make it work with React”** often wires a global socket that reconnects forever with stale JWTs in query strings (logged by proxies).

When the prompt is “add live updates,” the model rarely adds: Origin allowlist, ticket-based handshake, message schema (Zod/JSON Schema), rate limits, or forced `wss://`.

---