---
source: "common/agent-security.md"
title: "AI Agent Security — Autonomous Agent Attack Surface, Tool Poisoning, Memory Attacks"
heading: "6. Prevention Checklist"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [agent, code, common-vuln, configuration, explanation, secure, threat, vulnerability, vulnerable]
chunk: 7/10
---

## 6. Prevention Checklist

- [ ] **1. Principle of least privilege** — Grant filesystem/command/network access scoped to the specific task. Never use wildcard `["*"]` permissions.
- [ ] **2. Sandbox enforcement** — Run agents in containers with network disabled by default, read-only root filesystem, and dropped capabilities.
- [ ] **3. Human approval gates** — Require explicit user confirmation for write operations, network calls, package installations, and destructive commands.
- [ ] **4. MCP server allowlisting** — Only connect to pre-vetted, pinned-version MCP servers. Block arbitrary server URLs.
- [ ] **5. Tool response validation** — Validate tool output schemas before passing content to the LLM context. Reject responses that don't match expected format.
- [ ] **6. Credential isolation** — Never store credentials in agent config files. Use secrets management (Vault, env vars, cloud secret stores) with per-session tokens.
- [ ] **7. Session timeouts** — Terminate agent sessions after idle periods. Destroy session state, credentials, and memory.
- [ ] **8. Audit logging** — Log every tool call, file access, command execution, and network request with agent ID, session ID, timestamp, and outcome.
- [ ] **9. Behavioral monitoring** — Monitor agent behavior at runtime (syscall level). Detect anomalous patterns like mass file reads, unexpected outbound connections, or credential access.
- [ ] **10. Memory integrity** — Encrypt long-term memory stores. Validate memory retrieval outputs before processing. Implement memory versioning to detect tampering.
- [ ] **11. Supply chain scanning** — Scan every package the agent installs against known vulnerability databases. Block installation of packages with suspicious metadata.
- [ ] **12. Regular updates** — Keep agent software, sandbox runtime, and MCP implementations patched. Subscribe to vendor security advisories (GitHub Advisory DB for agent CVEs).
- [ ] **13. Assume-compromise architecture** — Design agent infrastructure so that a fully compromised reasoning system cannot cause disproportionate damage (the Parallax principle: Cognitive-Executive Separation).

---