---
source: "common/agent-security.md"
title: "AI Agent Security — Autonomous Agent Attack Surface, Tool Poisoning, Memory Attacks"
heading: "8. Vibe-Coding Red Flags"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [agent, code, common-vuln, configuration, explanation, secure, threat, vulnerability, vulnerable]
chunk: 9/10
---

## 8. Vibe-Coding Red Flags

Watch for these patterns in vibe-coded agent configurations:

- [ ] **1. `"permissions": {"filesystem": ["*"]}`** — Full filesystem access with no scope boundaries.
- [ ] **2. Agent running outside a container** — No sandbox, no read-only filesystem, no network restrictions.
- [ ] **3. API keys in plaintext config files** — Credentials stored in `.env` or `settings.json` that the agent reads.
- [ ] **4. `pip install` / `npm install` in agent-generated code** — Auto-installing packages without integrity verification.
- [ ] **5. Agent approving its own destructive operations** — No human-in-the-loop for writes, network calls, or deletions.
- [ ] **6. Connecting to arbitrary MCP servers** — No allowlisting, no server vetting, no response validation.
- [ ] **7. Long-running agent sessions with no timeout** — Sessions that stay alive for hours, accumulating context and attack surface.
- [ ] **8. Using `latest` package versions in agent instructions** — Unpinned dependencies bypass lockfile integrity.
- [ ] **9. Agent with both file read AND network write access** — The "lethal trifecta" (Simon Willison): private data + untrusted content + external communication.
- [ ] **10. No audit logging of agent actions** — No way to determine what the agent did after a compromise.
- [ ] **11. Memory persistence without integrity checking** — Long-term memory stores that aren't encrypted or validated.
- [ ] **12. Agent generating and executing code in the same step** — No separation between code generation and code execution (violates Cognitive-Executive Separation).

---