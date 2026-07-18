---
source: "common/agent-security.md"
title: "AI Agent Security — Autonomous Agent Attack Surface, Tool Poisoning, Memory Attacks"
heading: "2. Agent Threat Categories"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [agent, code, common-vuln, configuration, explanation, secure, threat, vulnerability, vulnerable]
chunk: 3/10
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