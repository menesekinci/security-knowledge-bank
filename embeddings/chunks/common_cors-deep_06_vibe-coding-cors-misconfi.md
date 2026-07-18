---
source: "common/cors-deep.md"
title: "CORS Deep Dive — Preflight Bypass, Null Origin, Credentials Mode, Wildcard vs Specific, Vibe Coding Misconfigs"
heading: "Vibe Coding CORS Misconfigs — Common Patterns"
category: "common-vuln"
language: "common"
severity: "medium"
tags: [coding, common-vuln, cors, headers, vibe, vulnerability, what]
chunk: 6/10
---

## Vibe Coding CORS Misconfigs — Common Patterns

### Pattern 1: "CORS for Everyone" Middleware
```javascript
// 🔴 From ChatGPT: Permissive CORS for "easy development"
app.use(cors()); // Default: allows ALL origins! Never use in production

// 🔴 Another common AI output:
app.use((req, res, next) => {
    res.header('Access-Control-Allow-Origin', '*');    // Wildcard
    res.header('Access-Control-Allow-Methods', '*');   // All methods
    res.header('Access-Control-Allow-Headers', '*');   // All headers
    next();
});
```

### Pattern 2: "Token in Query String" Workaround
```javascript
// 🔴 AI-generated workaround when CORS blocks custom headers
fetch(`/api/user?token=${localStorage.getItem('jwt')}`)
// Token in URL → leaks to server logs, browser history, referer header
```

### Pattern 3: CORS Proxy for "Debugging"
```javascript
// 🔴 AI suggests running a CORS proxy to "fix" frontend-backend issues
const corsProxy = require('cors-anywhere');
corsProxy.createServer().listen(8080);
// Removes all CORS protection — attackers love this
```

---