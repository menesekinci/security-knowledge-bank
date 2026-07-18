---
source: "common/agent-permission-model.md"
title: "AI Agent Permission Models — Design Reference for Least-Privilege Agents"
heading: "2. Comparison of Real Agent Permission Models"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [approach, common, common-vuln, comparison, implementation, models, patterns, permission, recommended]
chunk: 3/7
---

## 2. Comparison of Real Agent Permission Models

### 2.1 Claude Code (Anthropic)

| Aspect | Detail |
|--------|--------|
| **Permission Model** | Approval-based + repository trust |
| **Filesystem** | Workspace-scoped (read + write within project); prompts for trust on first use |
| **Commands** | User approves each shell command; diff view shown before execution |
| **Network** | Allowed (needed for API calls); API key managed via env/credential store |
| **MCP Servers** | Consent dialog on first connection; version-pinned |
| **Human-in-Loop** | ✅ Required for writes, destructive commands, MCP server adds |
| **Sandbox** | None by default (runs with user privileges); external sandboxing recommended |
| **Known Issues** | CVE-2025-59536 (pre-trust RCE), CVE-2026-21852 (API key leak before trust) |

**Lessons from Claude Code CVEs:** The pre-trust RCE (CVE-2025-59536) demonstrated that trust dialogs must be **architecturally enforced**, not merely advisory. If code can execute before the user confirms trust, the permission model is broken at the architecture level, not the configuration level.

### 2.2 Codex CLI (OpenAI)

| Aspect | Detail |
|--------|--------|
| **Permission Model** | Container sandbox + auto-approve for scoped actions |
| **Filesystem** | Container-scoped; reads/writes confined to session workspace |
| **Commands** | Auto-approved within container sandbox (network disabled by default) |
| **Network** | Disabled by default; explicit enable for API access |
| **Human-in-Loop** | Not required for in-sandbox operations; required for out-of-sandbox file access |
| **Sandbox** | ✅ Docker/Firecracker container with dropped capabilities, read-only root |
| **Known Issues** | CVE-2025-59532 (sandbox escape via model-generated cwd confusion) |

**Lessons from Codex CLI CVEs:** A sandbox is only as strong as its boundary validation. CVE-2025-59532 showed that trusting model-generated path values (even within a sandbox) can circumvent the workspace boundary. All path inputs must be **canonicalized** at the enforcement layer, not at the LLM layer.

### 2.3 Cursor Agent

| Aspect | Detail |
|--------|--------|
| **Permission Model** | MCP-scoped + per-tool approval |
| **Filesystem** | Project-scoped (Cursor workspace); reads/writes within project |
| **Commands** | Terminal commands require user approval |
| **Network** | MCP-controlled; domain allowlisting per server |
| **Human-in-Loop** | ✅ Required for MCP server adds, terminal commands, file writes outside workspace |
| **Sandbox** | Requires external Docker/devcontainer config |

### 2.4 OpenAI Codex (Function-Calling)

| Aspect | Detail |
|--------|--------|
| **Permission Model** | Function-calling scoped (API-level) |
| **Filesystem** | No direct filesystem access (runs on OpenAI servers) |
| **Commands** | No shell execution (server-side) |
| **Network** | Network requests only via defined function schemas |
| **Human-in-Loop** | Configurable per function call |
| **Sandbox** | ✅ Server-side isolation |

---