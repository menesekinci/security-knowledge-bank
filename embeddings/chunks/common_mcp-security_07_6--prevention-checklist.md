---
source: "common/mcp-security.md"
title: "MCP (Model Context Protocol) Security"
heading: "6. Prevention Checklist"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [code, common-vuln, explanation, owasp, secure, vulnerability, vulnerable]
chunk: 7/10
---

## 6. Prevention Checklist

- [ ] **Pin tool versions and sign schemas** at install time; alert on any post-install description drift (prevents rug pulls)
- [ ] **Validate all tool descriptions** for hidden instructions — scan for HTML tags, code blocks, file paths, and base64-encoded content
- [ ] **Implement OAuth 2.1 with PKCE** as the default authentication mechanism; avoid static API keys and PATs
- [ ] **Use short-lived, scoped tokens** with automated expiry — never long-lived credentials
- [ ] **Sandbox MCP server execution** — run in containers with read-only filesystems and deny-by-default network egress
- [ ] **Treat all retrieved content as untrusted** — context isolation between user instructions and external data
- [ ] **Maintain an AI Bill of Materials (AIBOM)** for every MCP server, connector, and dependency
- [ ] **Apply SCA policies before agents pull new tools** — not after installation
- [ ] **Implement immutable audit logging** for all tool invocations, context changes, and agent actions
- [ ] **Run continuous discovery** of MCP servers across repos, developer machines, CI runners, and production
- [ ] **Require human-in-the-loop confirmation** for sensitive tool invocations (filesystem writes, network calls, execution)
- [ ] **Enforce least privilege at the capability level** — not application level — define per-tool permissions
- [ ] **Monitor for tool description drift** — compare approved schemas against runtime schemas
- [ ] **Use MCP-aware security scanners** (e.g., Invariant Labs' MCP-Scan) to audit servers before deployment
- [ ] **Enable behavioral monitoring** on agent action sequences to catch multi-step attacks

---