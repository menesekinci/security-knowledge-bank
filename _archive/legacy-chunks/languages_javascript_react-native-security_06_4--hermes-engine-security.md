---
source: "languages/javascript/react-native-security.md"
title: "React Native Security Deep Dive"
category: "language-vuln"
language: "javascript"
chunk: 6
total_chunks: 13
heading: "4. Hermes Engine Security"
---

## 4. Hermes Engine Security

### JavaScript Injection

The Hermes engine precompiles JavaScript to bytecode. While this provides some protection against source code inspection, it doesn't prevent runtime injection.

**Vulnerable Code:**
```javascript
// 💀 VULNERABLE — Dynamic code execution in Hermes
const userCode = await fetchUserScript();
// Hermes supports eval() — dangerous with untrusted input
eval(userCode);  // 💀 Code injection
```

**Secure Code:**
```javascript
// ✅ SECURE — Avoid dynamic code execution
// Hermes supports Function() constructor too — avoid both!

// Use sandboxed evaluation instead
// Or better — don't execute user code at all

// If you must evaluate expressions, use a safe expression parser
import { compileExpression } from "filtrex";

const safeExpr = compileExpression(userInput);
const result = safeExpr({ items: data });
```

### Hermes Debugger Exposure

```javascript
// 💀 VULNERABLE — Debugger enabled in production
// metro.config.js or .env
HERMES_DEBUGGER_ENABLED = true;  // 💀 Exposes bytecode debug interface
```

```javascript
// ✅ SECURE — Disable debugger in production builds
// .env.production
HERMES_DEBUGGER_ENABLED = false;

// metro.config.js
module.exports = {
  transformer: {
    minifierConfig: {
      mangle: { reserved: [] },  // Obfuscate production code
    },
  },
};
```

---