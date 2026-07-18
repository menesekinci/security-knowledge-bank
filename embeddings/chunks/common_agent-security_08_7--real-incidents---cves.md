---
source: "common/agent-security.md"
title: "AI Agent Security — Autonomous Agent Attack Surface, Tool Poisoning, Memory Attacks"
heading: "7. Real Incidents / CVEs"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [agent, code, common-vuln, configuration, explanation, secure, threat, vulnerability, vulnerable]
chunk: 8/10
---

## 7. Real Incidents / CVEs

All following CVEs have been verified against NVD or GitHub Security Advisories.

### CVE-2026-25049 — n8n Type Confusion RCE (CVSS 9.4)

| Field | Value |
|-------|-------|
| **Published** | February 4, 2026 |
| **CVSS 4.0** | 9.4 (Critical) — CNA: GitHub |
| **CWE** | CWE-913 (Improper Control of Dynamically-Managed Code Resources) |
| **Affected** | n8n < 1.123.17, 2.0.0 ≤ n8n < 2.5.2 |
| **Description** | An authenticated user with permission to create or modify workflows could abuse crafted expressions in workflow parameters to trigger unintended system command execution on the host running n8n. This is a type confusion vulnerability in the expression evaluation engine — the agent-like workflow tool treated user-supplied expressions as executable code rather than data. |
| **Impact** | Full host compromise: file read, credential theft, lateral movement. |
| **Fix** | Patched in n8n 1.123.17 and 2.5.2. |
| **Source** | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-25049), [GHSA-6cqr-8cfr-67f8](https://github.com/n8n-io/n8n/security/advisories/GHSA-6cqr-8cfr-67f8) |

### CVE-2025-68613 — n8n Expression Injection RCE (CVSS 9.9)

| Field | Value |
|-------|-------|
| **Published** | December 19, 2025 |
| **CVSS 3.1** | 9.9 (Critical) — CNA: GitHub |
| **CWE** | CWE-913 (Improper Control of Dynamically-Managed Code Resources) |
| **Affected** | n8n ≥ 0.211.0, < 1.120.4; 1.121.0 |
| **Description** | A critical RCE vulnerability in n8n's workflow expression evaluation system. Expressions supplied by authenticated users during workflow configuration could be evaluated in an execution context not sufficiently isolated from the underlying runtime, allowing arbitrary code execution with the privileges of the n8n process. |
| **Impact** | Full instance compromise. Added to **CISA Known Exploited Vulnerabilities Catalog** on March 11, 2026. Exploited by ZeroBot malware (Akamai, Feb 2026). |
| **Fix** | Patched in n8n 1.120.4, 1.121.1, 1.122.0. |
| **Source** | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2025-68613), [GHSA-v98v-ff95-f3cp](https://github.com/n8n-io/n8n/security/advisories/GHSA-v98v-ff95-f3cp) |

### CVE-2025-59532 — Codex CLI Sandbox Escape (CVSS 8.6)

| Field | Value |
|-------|-------|
| **Published** | September 22, 2025 |
| **CVSS 4.0** | 8.6 (High) — CNA: GitHub |
| **CWE** | CWE-20 (Improper Input Validation) |
| **Affected** | Codex CLI 0.2.0 to 0.38.0 |
| **Description** | Due to a bug in the sandbox configuration logic, Codex CLI could treat a model-generated cwd as the sandbox's writable root, including paths outside the user's session folder. This bypassed the intended workspace boundary and enabled arbitrary file writes and command execution where the Codex process had permissions. |
| **Impact** | Sandbox escape leading to arbitrary file writes and code execution on the host. |
| **Fix** | Patched in Codex CLI 0.39.0 and Codex IDE extension 0.4.12. |
| **Source** | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2025-59532), [GHSA-w5fx-fh39-j5rw](https://github.com/openai/codex/security/advisories/GHSA-w5fx-fh39-j5rw) |

### CVE-2025-59536 — Claude Code Pre-Trust RCE (CVSS 8.7)

| Field | Value |
|-------|-------|
| **Published** | October 3, 2025 |
| **CVSS 4.0** | 8.7 (High) — CNA: GitHub |
| **CWE** | CWE-94 (Code Injection) |
| **Affected** | Claude Code < 1.0.111 |
| **Description** | Claude Code could be tricked to execute code contained in a project **before** the user accepted the startup trust dialog. The startup trust dialog bug allowed malicious project files (Hooks in `.claude/settings.json`) to execute shell commands before the user confirmed trust. Additionally, MCP consent could be bypassed via `.mcp.json` settings. |
| **Impact** | Remote code execution in developer environments simply by cloning a malicious repository and opening it with Claude Code. API key exfiltration possible. |
| **Fix** | Fixed in Claude Code 1.0.111 (automatically via auto-update). |
| **Source** | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2025-59536), [GHSA-4fgq-fpq9-mr3g](https://github.com/anthropics/claude-code/security/advisories/GHSA-4fgq-fpq9-mr3g) |

### CVE-2026-21852 — Claude Code API Key Exfiltration (CVSS 7.5)

| Field | Value |
|-------|-------|
| **Published** | January 21, 2026 |
| **CVSS 3.1** | 7.5 (High) — NIST |
| **CWE** | CWE-522 (Insufficiently Protected Credentials) |
| **Affected** | Claude Code < 2.0.65 |
| **Description** | An attacker-controlled repository could include a settings file that sets `ANTHROPIC_BASE_URL` to an attacker-controlled endpoint. When the repository was opened, Claude Code would read the configuration and immediately issue API requests before showing the trust prompt, leaking the user's Anthropic API key in the request. |
| **Impact** | API key theft. In environments using Anthropic Workspaces, a single stolen key exposes the entire team's data. |
| **Fix** | Fixed in Claude Code 2.0.65. |
| **Source** | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-21852), [GHSA-jh7p-qr78-84p7](https://github.com/anthropics/claude-code/security/advisories/GHSA-jh7p-qr78-84p7) |

### CVE-2025-32711 — EchoLeak: Zero-Click Copilot Data Exfiltration (CVSS 9.3)

| Field | Value |
|-------|-------|
| **Published** | June 11, 2025 |
| **CVSS 3.1** | 9.3 (Critical) — CNA: Microsoft |
| **CWE** | CWE-74 (Injection) |
| **Affected** | Microsoft 365 Copilot |
| **Description** | The first real-world zero-click prompt injection exploit in a production AI agent. A crafted email slipped hidden instructions into Microsoft 365 Copilot. Copilot then sent sensitive organizational data to an attacker-controlled destination without any user click or interaction required. |
| **Impact** | Data exfiltration of sensitive organizational data from email, documents, and internal communications. No user interaction required. |
| **Fix** | Patched by Microsoft via service-side update (June 2025). |
| **Source** | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2025-32711), [MSRC](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-32711) |

### CVE-2026-32211 — Azure MCP Server No Authentication (CVSS 9.1)

| Field | Value |
|-------|-------|
| **Published** | April 2, 2026 |
| **CVSS 3.1** | 9.1 (Critical) — CNA: Microsoft |
| **CWE** | CWE-306 (Missing Authentication for Critical Function) |
| **Affected** | Microsoft Azure Web Apps MCP Server |
| **Description** | Microsoft shipped an official MCP server for Azure DevOps with **missing authentication**. No authentication was required to access the server's critical functions, allowing unauthorized attackers to disclose sensitive information (API keys, tokens, configuration data) over the network. |
| **Impact** | Unauthenticated access to Azure DevOps resources including API keys and tokens. Full information disclosure. |
| **Fix** | Service-side fix applied by Microsoft. |
| **Source** | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-32211), [MSRC](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-32211) |

### Claude Code Source Map Leak (March 2026)

**Not a CVE, but a significant incident.** On March 31, 2026, Anthropic accidentally shipped the full source code of Claude Code to the public npm registry via a misconfigured `.gitignore` / source map configuration. The exposed source maps allowed anyone to reconstruct Claude Code's readable source code. While this was a configuration/process failure rather than an agent vulnerability, it highlighted that **the build and deployment pipeline for agent tools is itself a critical attack surface**. Exposed source code can reveal internal API endpoints, authentication mechanisms, and zero-day vulnerabilities in the agent itself.

**Sources:** [Zscaler](https://www.zscaler.com/blogs/security-research/anthropic-claude-code-leak), [Penligent](https://www.penligent.ai/hackinglabs/claude-code-source-map-leak-what-was-exposed-and-what-it-means/)

### Additional Notable Incidents

| Incident | Date | Description |
|----------|------|-------------|
| **OpenClaw ClawHavoc** | Feb 2026 | 1,184 malicious skills on ClawHub marketplace; 9 CVEs, 3 with public exploit code ([Cyber Desserts](https://blog.cyberdesserts.com/ai-agent-security-risks/)) |
| **Mexico AI-Directed Attack** | Dec 2025–Jan 2026 | Attacker used Claude + ChatGPT to breach 7+ Mexican government agencies; 195M taxpayer records exfiltrated ([SecurityWeek](https://www.securityweek.com/)) |
| **JADEPUFFER Ransomware Agent** | 2026 | Fully autonomous agentic ransomware targeting databases ([Sysdig](https://www.sysdig.com/blog/jadepuffer-agentic-ransomware-for-automated-database-extortion)) |

---