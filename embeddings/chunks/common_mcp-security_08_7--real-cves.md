---
source: "common/mcp-security.md"
title: "MCP (Model Context Protocol) Security"
heading: "7. Real CVEs"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [code, common-vuln, explanation, owasp, secure, vulnerability, vulnerable]
chunk: 8/10
---

## 7. Real CVEs

All CVEs below have been web-verified against NVD and/or the assigning CNA.

### CVE-2025-6514 — mcp-remote OS Command Injection (CRITICAL)
- **CVSS 9.6** | **CWE-78** (OS Command Injection)
- **Affected:** mcp-remote v0.0.5–0.1.15
- **Fixed in:** v0.1.16
- **Published:** July 9, 2025 | **Source:** JFrog Security Research
- **Description:** mcp-remote is exposed to OS command injection when connecting to untrusted MCP servers via a crafted `authorization_endpoint` response URL. Attackers can achieve full RCE on the client machine. The package had 437,000+ downloads before disclosure.
- **Impact:** Full system compromise on Windows; arbitrary executable execution on macOS/Linux.
- **NVD:** https://nvd.nist.gov/vuln/detail/CVE-2025-6514
- **JFrog Advisory:** https://jfrog.com/blog/2025-6514-critical-mcp-remote-rce-vulnerability

### CVE-2025-6515 — oatpp-mcp Session Hijacking (MEDIUM)
- **CVSS 6.8** | **CWE-330** (Insufficient Randomness)
- **Affected:** oatpp-mcp (all versions)
- **Published:** October 20, 2025 | **Source:** JFrog Security Research
- **Description:** The MCP SSE endpoint in oatpp-mcp returns an instance pointer as the session ID, which is neither unique nor cryptographically secure. Network attackers with access to the server can guess future session IDs and hijack legitimate client MCP sessions, returning malicious responses.
- **Impact:** Session hijacking, response manipulation, prompt injection delivery.
- **NVD:** https://nvd.nist.gov/vuln/detail/CVE-2025-6515

### CVE-2026-24042 — Appsmith Missing Authorization (CRITICAL)
- **CVSS 9.4** (GitHub CNA secondary; NVD adopted a 9.8 primary) | **CWE-862** (Missing Authorization)
- **Affected:** Appsmith ≤ v1.94
- **Published:** January 21, 2026 | **Source:** GitHub Security Lab
- **Description:** Publicly accessible apps allow unauthenticated users to execute unpublished (edit-mode) actions by sending `viewMode=false` to the execute endpoint. This bypasses the publish boundary where public viewers should only execute published actions.
- **MCP Relevance:** Appsmith is a platform for building admin panels and internal tools that often serves as the UI layer for MCP-connected workflows. The auth bypass vulnerability demonstrates the class of missing authorization flaws directly applicable to MCP server deployments.
- **NVD:** https://nvd.nist.gov/vuln/detail/CVE-2026-24042

### CVE-2026-25631 — n8n Credential Domain Validation Bypass (MEDIUM)
- **CVSS 5.3** (CVSS 4.0, GitHub CNA; NVD also lists a 6.5 v3.1 primary) | **CWE-20** (Improper Input Validation), **CWE-522** (Insufficiently Protected Credentials)
- **Affected:** n8n < v1.121.0
- **Published:** February 6, 2026 | **Source:** GitHub Security Lab
- **Description:** HTTP Request node's credential domain validation allows authenticated attackers to send requests with credentials to unintended domains, potentially leading to credential exfiltration. Affects users with wildcard domain patterns (e.g., `*.example.com`) in "Allowed domains" settings.
- **MCP Relevance:** n8n is a workflow automation platform that commonly integrates with MCP servers as an orchestrator. This credential domain validation flaw mirrors the insufficient credential protection patterns seen across MCP implementations.
- **NVD:** https://nvd.nist.gov/vuln/detail/CVE-2026-25631

### Additional MCP CVEs (Verified)

| CVE | Product | CVSS | Type | Source |
|-----|---------|------|------|--------|
| CVE-2025-49596 | Anthropic MCP Inspector | 9.4 | RCE via DNS rebinding | Oligo Security |
| CVE-2025-54136 | Cursor (MCPoison) | 7.2 | Persistent RCE via MCP config swap | Check Point |
| CVE-2025-54135 | Cursor (CurXecute) | — | RCE via MCP auto-start prompt injection | Aim Labs |
| CVE-2025-53110 | Filesystem MCP Server | 7.3 | Directory containment bypass | Trend Micro |
| CVE-2025-53109 | Filesystem MCP Server | 7.3 | Symlink bypass (CWE-59) | Trend Micro |
| CVE-2025-68143/44/45 | Anthropic Git MCP Server | — | Path traversal & argument injection | Cyata/Dark Reading |
| CVE-2026-33032 | nginx-ui MCP (MCPwn) | 9.8 | Auth bypass, actively exploited | Pluto Security |

---