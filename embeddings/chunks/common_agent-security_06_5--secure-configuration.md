---
source: "common/agent-security.md"
title: "AI Agent Security — Autonomous Agent Attack Surface, Tool Poisoning, Memory Attacks"
heading: "5. Secure Configuration & Fixes"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [agent, code, common-vuln, configuration, explanation, secure, threat, vulnerability, vulnerable]
chunk: 6/10
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