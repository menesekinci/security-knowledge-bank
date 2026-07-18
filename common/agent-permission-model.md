# AI Agent Permission Models — Design Reference for Least-Privilege Agents

**Severity:** Critical  
**CWE:** CWE-284 (Improper Access Control), CWE-266 (Incorrect Privilege Assignment), CWE-272 (Least Privilege Violation)  
**OWASP Agentic Top 10 (2026):** ASI03 (Identity & Privilege Abuse)  
**AI Generation Risk:** Very High

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

## 3. Recommended Approach: Layered Permission Model

The most robust permission model combines **capability + scope + human-in-loop** in a defense-in-depth architecture. This is inspired by the Parallax paradigm (arXiv:2604.12986) which proposes Cognitive-Executive Separation: the reasoning system must be structurally unable to execute actions, and the execution system must be structurally unable to reason about them.

### Architecture

```
┌─────────────────┐     ┌─────────────────┐     ┌──────────────────┐
│   Reasoning     │     │    Validator     │     │    Executor      │
│   (LLM Agent)   │────▶│  (Policy Engine) │────▶│  (Sandboxed)     │
│                 │     │                  │     │                  │
│  - Plans        │     │  - Checks caps   │     │  - Runs commands │
│  - Selects tools│     │  - Enforces      │     │  - Writes files  │
│  - Generates    │     │    scoping rules  │     │  - Network calls │
│    parameters   │     │  - Logs actions   │     │  - Revoked on    │
│                 │     │  - Requires       │     │    session end   │
│  NO direct      │     │    human approval │     │                  │
│  execution      │     │    for dangerous  │     │  NO reasoning    │
│  capability     │     │    ops            │     │  capability      │
└─────────────────┘     └─────────────────┘     └──────────────────┘
```

### Policy Matrix

| Operation | Default | Requires Human | Capability Required |
|-----------|---------|----------------|---------------------|
| File read (within workspace) | ✅ Allow | No | `file.read:{workspace}` |
| File read (outside workspace) | ❌ Deny | Yes | `file.read:{path}` |
| File write (scratch dir) | ✅ Allow | No | `file.write:{scratch}` |
| File write (source dir) | ❌ Deny | Yes | `file.write:{source}` |
| Git read commands | ✅ Allow | No | `git.read` |
| Git write commands | ❌ Deny | Yes | `git.write` |
| Package install | ❌ Deny | Yes | `pkg.install:{registry}` |
| Network: allowlisted domains | ✅ Allow | No | `net.connect:{domain}` |
| Network: arbitrary domains | ❌ Deny | Yes | `net.connect:any` |
| Credential access | ❌ Deny | Yes | `credential.read:{service}` |
| Shell: allowlisted commands | ✅ Allow | No | `shell.exec:{command}` |
| Shell: arbitrary commands | ❌ Deny | Yes | `shell.exec:any` |

---

## 4. Implementation Patterns

### 4.1 Capability Token Pattern

```python
from dataclasses import dataclass
from datetime import datetime, timedelta
import secrets

@dataclass
class Capability:
    resource: str      # e.g. "filesystem:/workspace/project/src"
    action: str        # e.g. "file.read"
    token: str         # cryptographically random
    expires_at: datetime
    max_bytes: int = None

class CapabilityManager:
    """Issues and validates capability tokens for agent operations."""
    
    def request_capability(self, agent_id: str, resource: str, action: str, ttl_minutes: int = 60) -> Capability:
        # Validate against policy
        self._enforce_policy(agent_id, resource, action)
        
        cap = Capability(
            resource=resource,
            action=action,
            token=secrets.token_urlsafe(32),
            expires_at=datetime.utcnow() + timedelta(minutes=ttl_minutes)
        )
        self._store[cap.token] = cap
        return cap
    
    def validate(self, token: str, resource: str, action: str) -> bool:
        cap = self._store.get(token)
        if not cap: return False
        if cap.expires_at < datetime.utcnow(): return False
        if cap.resource != resource: return False
        if cap.action != action: return False
        return True
```

### 4.2 Least-Privilege Sandbox Configuration

```yaml
# docker-compose.agent.yml — Secure Agent Sandbox
version: '3.8'
services:
  agent:
    build: ./agent
    read_only: true                    # Root filesystem is read-only
    tmpfs:
      - /tmp:noexec,nosuid,size=100m  # Temp dir with restrictions
      - /workspace/output:rw           # Explicit writable directory
    volumes:
      - ./project:/workspace/project:ro  # Read-only project mount
    cap_drop:
      - ALL                            # Drop all capabilities
    cap_add:
      - CAP_NET_BIND_SERVICE           # Only allow listening on ports (if needed)
    security_opt:
      - no-new-privileges:true         # Prevent privilege escalation
    network_mode: "none"               # No network by default
    environment:
      - AGENT_SESSION_ID=${SESSION_ID}
      - AGENT_TASK_SCOPE=task-${TASK_ID}
```

### 4.3 Approval Gate Middleware

```javascript
// Approval gate — interceptor pattern
class PermissionGate {
  constructor(approvalStrategy) {
    this.strategy = approvalStrategy;  // 'always', 'interactive', 'deny'
  }

  async enforce(action) {
    const decision = await this.evaluate(action);
    
    if (decision === 'deny') {
      throw new PermissionDeniedError(action, 'Operation not permitted');
    }
    
    if (decision === 'require_approval') {
      const approved = await this.strategy.getApproval(action);
      if (!approved) {
        throw new PermissionDeniedError(action, 'User denied operation');
      }
    }
    
    // Log approved action with full context
    logger.audit('agent_action', {
      action: action.type,
      resource: action.resource,
      agent_id: action.agentId,
      session_id: action.sessionId,
      timestamp: new Date().toISOString()
    });
    
    return true;
  }
}
```

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

## 6. References

1. [OWASP Top 10 for Agentic Applications (2026)](https://genai.owasp.org/)
2. [Parallax: Why AI Agents That Think Must Never Act (arXiv:2604.12986)](https://arxiv.org/html/2604.12986v1)
3. [IsolateGPT: Execution Isolation Architecture for LLM-Based Agentic Systems (arXiv:2403.04960)](https://arxiv.org/abs/2403.04960)
4. [Sysdig — Agentic AI Security Guide](https://www.sysdig.com/learn-cloud-native/agentic-ai-security)
5. [OpenAI Codex CLI — Sandbox Documentation](https://github.com/openai/codex)
6. [Anthropic Claude Code — Security Advisories](https://github.com/anthropics/claude-code/security/advisories)
7. [CoSAI — Securing the AI Agent Revolution: MCP Security (Jan 2026)](https://www.coalitionforsecureai.org/)
8. [CVE-2025-59532 — Codex CLI Sandbox Escape](https://nvd.nist.gov/vuln/detail/CVE-2025-59532)
9. [CVE-2025-59536 — Claude Code Pre-Trust RCE](https://nvd.nist.gov/vuln/detail/CVE-2025-59536)
10. [CVE-2026-21852 — Claude Code API Key Theft](https://nvd.nist.gov/vuln/detail/CVE-2026-21852)
11. [Ji et al., "Taming Various Privilege Escalation in LLM-Based Agent Systems: A MAC Framework" (arXiv:2601.11893)](https://arxiv.org/abs/2601.11893)
