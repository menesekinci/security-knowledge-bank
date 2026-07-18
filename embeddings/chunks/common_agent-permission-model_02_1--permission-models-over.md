---
source: "common/agent-permission-model.md"
title: "AI Agent Permission Models — Design Reference for Least-Privilege Agents"
heading: "1. Permission Models Overview"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [approach, common, common-vuln, comparison, implementation, models, patterns, permission, recommended]
chunk: 2/7
---

## 1. Permission Models Overview

AI agents require a permission model that governs what they can access, execute, and communicate with. Unlike traditional application permissions (which are typically static and pre-configured), agent permissions must operate at runtime, across dynamic tool-use chains, and often in non-deterministic execution flows. The following models represent the spectrum from "no security" to "fine-grained capability control."

### 1.1 No Restrictions (Full Access)

**Risk Level: 🚨 CRITICAL — Never use in production**

The agent has unfettered access to the filesystem, all shell commands, unrestricted network access, and automatic approval for every action.

```json
{
  "permissions": {
    "filesystem": {"read": ["*"], "write": ["*"]},
    "commands": {"allow": ["*"]},
    "network": {"allow": ["*"]},
    "autoApprove": ["*"]
  }
}
```

**Dangers:**
- Any prompt injection becomes full system compromise
- Credentials, SSH keys, and database contents are freely readable
- Malicious packages can be installed and executed
- Data exfiltration to any external endpoint

### 1.2 File-System Scoped

**Risk Level: 🟡 Moderate**

The agent's access is scoped to specific directories. Read-only by default, with explicit write paths.

```json
{
  "permissions": {
    "filesystem": {
      "read": ["/workspace/project/**"],
      "write": ["/workspace/project/src/**", "/workspace/project/output/**"],
      "deny": ["**/.env", "**/credentials*", "**/secrets*", "**/config.json"]
    }
  }
}
```

**Safe defaults:** Read access to the workspace only; write access only to designated output directories; explicit deny rules for sensitive file patterns.

### 1.3 Network Scoped

**Risk Level: 🟡 Moderate**

Outbound network connections are restricted to an allowlist of domains. Inbound connections are blocked by default.

```json
{
  "permissions": {
    "network": {
      "allow": ["api.github.com", "registry.npmjs.org", "pypi.org"],
      "deny": ["*"],
      "protocols": ["https"],
      "ports": [443]
    }
  }
}
```

### 1.4 Command Scoped

**Risk Level: 🟢 Safer**

Only a predefined allowlist of shell commands may be executed. Pattern-based allow/deny rules can be used for flexibility.

```json
{
  "permissions": {
    "commands": {
      "allow": ["npm run build", "npm test", "git status", "git diff", "git log"],
      "allowPatterns": ["^git (status|diff|log|add -p)$"],
      "deny": ["sudo", "rm -rf", "curl", "wget", "pip install", "npm install"]
    }
  }
}
```

### 1.5 Capability-Based (Fine-Grained)

**Risk Level: 🟢 Safest**

Each operation requires an explicit capability token. Capabilities are short-lived, task-scoped, and revoked on session end. This is the most secure model, analogous to OAuth scopes or AWS IAM policies.

```yaml
capabilities:
  - resource: "github:repo:my-org/my-project"
    actions: ["pull_request.read", "issue.read"]
    expiry: "30m"
  - resource: "filesystem:/workspace/project/src"
    actions: ["file.read", "file.write"]
    expiry: "1h"
  - resource: "network:api.github.com"
    actions: ["https.get", "https.post"]
    maxBytes: 1048576  # 1MB limit
```

---