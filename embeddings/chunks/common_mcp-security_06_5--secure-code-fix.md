---
source: "common/mcp-security.md"
title: "MCP (Model Context Protocol) Security"
heading: "5. Secure Code Fix"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [code, common-vuln, explanation, owasp, secure, vulnerability, vulnerable]
chunk: 6/10
---

## 5. Secure Code Fix

### 5.1 Input Validation (Tool Description Sanitization)

```python
from mcp import ToolValidator

@mcp.tool(validator=ToolValidator(
    max_description_length=500,
    block_html_tags=True,
    block_code_execution=True,
    block_file_paths=True
))
def add(a: int, b: int) -> int:
    """Adds two numbers. Pure numeric operation only."""
    return a + b
```

### 5.2 Path Traversal Prevention

```python
import os

ALLOWED_DIR = os.path.abspath("/workspace")

@mcp.tool()
def read_file(path: str) -> str:
    """Read a file from the workspace."""
    safe_path = os.path.normpath(os.path.join(ALLOWED_DIR, path))
    if not safe_path.startswith(ALLOWED_DIR):
        raise ValueError("Path traversal detected")
    with open(safe_path, "r") as f:
        return f.read()
```

### 5.3 Parameterized Command Execution

```typescript
server.tool("run_command", { 
  executable: z.enum(["ls", "cat", "pwd"]),
  args: z.array(z.string()).max(5)
}, async ({ executable, args }) => {
  // SAFE: parameterized, no shell, whitelisted commands only
  const result = spawnSync(executable, args, { shell: false });
  return { output: result.stdout.toString() };
});
```

### 5.4 OAuth 2.1 with PKCE

```javascript
const server = new MCPServer({
  transport: "https",
  auth: {
    scheme: "oauth2.1",
    pkce: true,
    audience: "https://mcp-server.example.com",
    token_expiry: "15m",
    refresh_enabled: true
  }
});
```

### 5.5 Capability Scoping

```javascript
server.defineCapability("filesystem", {
  // Scope to a single directory
  root: "/workspace/sandbox",
  // Read-only by default
  permissions: ["read"],
  // No network access
  network: "deny"
});
```

### 5.6 Container Sandboxing

```dockerfile
FROM alpine:latest
RUN adduser -D mcpsrv
USER mcpsrv
COPY --chown=mcpsrv:mcponly /workspace/sandbox /workspace
# Deny network egress
RUN echo "deny all" > /etc/iptables/rules
```

---