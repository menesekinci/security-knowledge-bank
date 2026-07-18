---
source: "common/agent-permission-model.md"
title: "AI Agent Permission Models — Design Reference for Least-Privilege Agents"
heading: "4. Implementation Patterns"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [approach, common, common-vuln, comparison, implementation, models, patterns, permission, recommended]
chunk: 5/7
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