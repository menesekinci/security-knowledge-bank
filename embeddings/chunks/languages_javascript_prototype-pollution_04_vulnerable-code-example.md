---
source: "languages/javascript/prototype-pollution.md"
title: "Prototype Pollution — JavaScript"
heading: "Vulnerable Code Example"
category: "language-vuln"
language: "javascript"
severity: "critical"
tags: [checklist, code, explanation, javascript, language-vuln, prevention, secure, vulnerability, vulnerable]
chunk: 4/8
---

## Vulnerable Code Example

### Full Exploit Chain: Prototype Pollution to Admin Access

```javascript
// 🚫 VULNERABLE — Complete application

// config.js — AI-generated config merger
function deepMerge(target, source) {
  for (const key in source) {
    if (source.hasOwnProperty(key)) {
      if (typeof source[key] === 'object' && source[key] !== null) {
        if (!target[key]) target[key] = {};
        deepMerge(target[key], source[key]);  // 💥
      } else {
        target[key] = source[key];
      }
    }
  }
  return target;
}

// server.js — AI-generated Express app
const express = require('express');
const app = express();
app.use(express.json());

const defaultConfig = {
  port: 3000,
  features: { darkMode: false }
};

// Attacker sends POST to /update with body:
// {"__proto__": {"isAdmin": true}, "port": 8080}
app.post('/update', (req, res) => {
  deepMerge(defaultConfig, req.body);  // 💥 Global prototype pollution
  res.json({ status: 'ok', config: defaultConfig });
});

// auth.js — AI-generated auth check
app.get('/admin', (req, res) => {
  const user = getUser(req.session.userId);
  
  // This check is now bypassed!
  if (user.isAdmin) {  // 💥 Every user is admin — inherits from Object.prototype
    res.send('Admin panel');
  } else {
    res.status(403).send('Forbidden');
  }
});
```

### Pollution via constructor.prototype

```javascript
// 🚫 VULNERABLE — Less obvious but equally dangerous
const attackerInput = JSON.parse(`
  {
    "constructor": {
      "prototype": {
        "bypassAuth": true
      }
    }
  }
`);

merge(appConfig, attackerInput);

// Now ALL objects have bypassAuth = true
console.log({}.bypassAuth);  // true

// This can bypass any property check in the application
function checkPermission(user, resource) {
  if (user.bypassAuth) return true;  // 💥 Always true!
  // ... real check
}
```

---