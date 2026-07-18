---
source: "common/mcp-security.md"
title: "MCP (Model Context Protocol) Security"
heading: "2. OWASP MCP Top 10 Summary"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [code, common-vuln, explanation, owasp, secure, vulnerability, vulnerable]
chunk: 3/10
---

## 2. OWASP MCP Top 10 Summary

The [OWASP MCP Top 10](https://owasp.org/www-project-mcp-top-10/) (v0.1, 2025) is the first OWASP framework dedicated to MCP attack surfaces. Below is a summary of all ten risk categories:

| ID | Risk | Primary Defense |
|---|---|---|
| **MCP01** | Token Mismanagement & Secret Exposure | Short-lived, scoped tokens; secrets detection |
| **MCP02** | Privilege Escalation via Scope Creep | Least-privilege scopes; automated scope expiry |
| **MCP03** | Tool Poisoning | Signed, pinned tools; description scanning |
| **MCP04** | Supply Chain Attacks & Dependency Tampering | Signed components; AIBOM and provenance |
| **MCP05** | Command Injection & Execution | Input validation; sandboxed execution |
| **MCP06** | Intent Flow Subversion (Prompt Injection via Context) | Context isolation; instruction quarantine |
| **MCP07** | Insufficient Authentication & Authorization | OAuth 2.1 + MFA; per-server audience validation |
| **MCP08** | Lack of Audit & Telemetry | Immutable audit logs; behavioral monitoring |
| **MCP09** | Shadow MCP Servers | Continuous discovery; allowlist enforcement |
| **MCP10** | Context Injection & Over-Sharing | Scoped context windows; ephemeral memory |

**MCP01 — Token Mismanagement & Secret Exposure:** Hard-coded credentials, long-lived tokens, and secrets stored in model memory or protocol logs expose connected systems. Astrix's October 2025 audit of 5,200+ MCP servers found 53% rely on static API keys/PATs, only 8.5% use OAuth, and 79% pass keys via environment variables. GitGuardian found 24,008 secrets in MCP-related config files on public GitHub, of which 2,117 were still valid.

**MCP02 — Privilege Escalation via Scope Creep:** Loosely defined permissions expand over time. Broad-scope PATs enabled the GitHub MCP "toxic agent flow" attack where a poisoned issue body redirected an agent with both public/private repo access to exfiltrate private code.

**MCP03 — Tool Poisoning:** Attackers embed malicious instructions in tool descriptions (metadata) that are invisible to users but read by AI models as trusted commands. Sub-techniques include rug pulls (silent redefinition after install), schema poisoning, and tool shadowing. Discovered by Invariant Labs in April 2025.

**MCP04 — Supply Chain Attacks:** Compromised dependencies in MCP servers. CVE-2025-6514 (mcp-remote, CVSS 9.6) affected 437,000+ downloads. The first tracked malicious MCP server (postmark-mcp on npm) silently BCC'd processed emails to an attacker domain.

**MCP05 — Command Injection & Execution:** 43% of tested MCP servers vulnerable to command injection (Equixly, 2025-2026); 34% expose APIs susceptible to command injection across 2,614 implementations (Endor Labs, 2025).

**MCP06 — Intent Flow Subversion:** Malicious instructions embedded in retrieved content (documents, web pages, GitHub issues) hijack the agent's reasoning. HackerOne reported a 540% surge in prompt-injection vulnerability reports.

**MCP07 — Insufficient Authentication:** 492 MCP servers exposed to the public internet with zero authentication (Trend Micro, July 2025), rising to 1,467 in follow-up scans. Only 8.5% of all MCP servers use OAuth.

**MCP08 — Lack of Audit & Telemetry:** Most MCP deployments lack immutable logs of tool invocations, making incident response nearly impossible. This amplifies every other risk.

**MCP09 — Shadow MCP Servers:** Unapproved MCP deployments outside security governance. 81% of organizations lack full visibility into AI usage across the SDLC (Cycode, 2026).

**MCP10 — Context Injection & Over-Sharing:** Shared or persistent context windows leak data across users, tasks, or tenants. Cross-tenant exposure documented in early MCP deployments.

---