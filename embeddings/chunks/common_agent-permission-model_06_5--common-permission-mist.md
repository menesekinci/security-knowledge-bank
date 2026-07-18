---
source: "common/agent-permission-model.md"
title: "AI Agent Permission Models — Design Reference for Least-Privilege Agents"
heading: "5. Common Permission Mistakes"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [approach, common, common-vuln, comparison, implementation, models, patterns, permission, recommended]
chunk: 6/7
---

## 5. Common Permission Mistakes

### Mistake 1: Using Auto-Approve for Everything

```javascript
// ❌ DANGEROUS — auto-approves ALL operations
const agent = createAgent({
  autoApprove: ['*']
});

// ✅ SAFE — auto-approve only read operations
const agent = createAgent({
  autoApprove: ['file.read', 'git.status', 'git.diff'],
  requireApproval: [
    'file.write',
    'file.delete',
    'network.post',
    'package.install',
    'shell.exec'
  ]
});
```

### Mistake 2: Symlink Traversal via Filesystem Scope

```python
# ❌ DANGEROUS — agent can follow symlinks outside workspace
ALLOWED_PATHS = ["/workspace/project/"]

def check_path(path):
    # String prefix check — bypassed by symlink /../ traversal
    return path.startswith(ALLOWED_PATHS[0])

# ✅ SAFE — canonicalize before checking
import os
def check_path_safe(path):
    real_path = os.path.realpath(path)  # Resolves symlinks, .., .
    return real_path.startswith(ALLOWED_PATHS[0])
```

### Mistake 3: Granting Read + Network Write Together

```yaml
# ❌ DANGEROUS — "lethal trifecta" (Simon Willison)
# Agent can read sensitive files AND send them anywhere
permissions:
  filesystem:
    read: ["/workspace/**", "/home/user/.ssh/**"]  # SSH keys readable
  network:
    allow: ["*"]  # Any endpoint reachable

# ✅ SAFE — read isolation from network
permissions:
  filesystem:
    read: ["/workspace/project/src/**"]
    deny: ["**/.ssh/**", "**/.env", "**/credentials*"]
  network:
    allow: ["api.github.com"]  # Only known, necessary endpoints
```

### Mistake 4: No Expiry on Capabilities

```javascript
// ❌ DANGEROUS — credential persists beyond task lifetime
const credential = await agent.getCredential('aws');
// credential is valid indefinitely

// ✅ SAFE — short-lived, session-scoped tokens
const credential = await agent.getSessionToken({
  scope: 's3:read-only',
  ttl: '15m',
  session: taskId
});
```

### Mistake 5: Trusting Model-Generated Path Boundaries

```python
# ❌ DANGEROUS — CVE-2025-59532 pattern
# Trusting model-generated cwd as sandbox boundary
sandbox_root = model_generated_cwd  # Attacker controls this

# ✅ SAFE — enforce boundary from trusted source
sandbox_root = os.path.realpath(user_started_cwd)  # User's actual starting dir
assert sandbox_root.startswith(TRUSTED_BASE)
```

---