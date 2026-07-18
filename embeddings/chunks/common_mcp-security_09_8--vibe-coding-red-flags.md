---
source: "common/mcp-security.md"
title: "MCP (Model Context Protocol) Security"
heading: "8. Vibe-Coding Red Flags"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [code, common-vuln, explanation, owasp, secure, vulnerability, vulnerable]
chunk: 9/10
---

## 8. Vibe-Coding Red Flags

Watch for these indicators that AI-generated MCP code may introduce security vulnerabilities:

- [ ] **Tool descriptions exceed 200 characters** — likely contains hidden instructions or prompt injection payloads
- [ ] **Tool accepts a `sidenote`, `extra`, `context`, or `metadata` catch-all parameter** — data exfiltration vector
- [ ] **Server uses `exec()`, `subprocess`, or `shell=True`** — command injection waiting to happen
- [ ] **File read/write tools lack path normalization** — path traversal vulnerability
- [ ] **No authentication middleware** — server accessible to any network caller
- [ ] **Hard-coded API keys, tokens, or `Authorization` headers in configuration** — credential exposure
- [ ] **Server runs on `0.0.0.0` with no firewall** — exposed to the internet (492 such servers found by Trend Micro)
- [ ] **Tool descriptions mention `<IMPORTANT>`, `<HIDDEN>`, or `<!--` HTML comments** — potential injection placeholder
- [ ] **`npx` or `pip install` commands without version pinning** — supply chain risk (CVE-2025-6514 vector)
- [ ] **Network calls to user-supplied URLs without validation** — SSRF vector (36.7% of servers vulnerable)
- [ ] **No request rate limiting or recursion protection** — DoS via infinite tool call loops
- [ ] **Agent context is shared across users or sessions** — context over-sharing (MCP10)

---