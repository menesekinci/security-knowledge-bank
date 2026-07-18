---
source: "common/prototype-pollution.md"
title: "Prototype Pollution"
heading: "Vulnerable Code Examples"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [checklist, code, common-vuln, fixed, prevention, vibe, vulnerable, what]
chunk: 4/8
---

## Vulnerable Code Examples

### Basic Prototype Pollution

```javascript
// 🔴 VULNERABLE: unsafe merge function
function merge(target, source) {
    for (const key in source) {
        if (typeof source[key] === 'object') {
            if (!target[key]) target[key] = {};
            merge(target[key], source[key]);
        } else {
            target[key] = source[key];
        }
    }
}

const config = { theme: 'dark' };
const userInput = JSON.parse('{"__proto__": {"admin": true}}');
merge(config, userInput);

// Now EVERY object has admin: true
console.log({}.admin);  // true — prototype was polluted!
console.log(config.admin);  // true
```

### Object.assign() is NOT Safe

```javascript
// 🔴 VULNERABLE: Object.assign doesn't protect __proto__
const userSettings = { theme: 'light' };
const malicious = JSON.parse('{"__proto__": {"isAdmin": true}}');
Object.assign(userSettings, malicious);

// __proto__ sets the prototype directly
console.log({}.isAdmin);  // true
```

### jQuery $.extend()

```javascript
// 🔴 VULNERABLE: jQuery extend (old versions)
const target = {};
$.extend(true, target, JSON.parse('{"__proto__": {"polluted": true}}'));
```

### Safe Defaults Pattern — Vulnerable

```javascript
// 🔴 VULNERABLE: deep merging user config with defaults
const DEFAULTS = { port: 3000, host: 'localhost' };

function startServer(userConfig) {
    const config = { ...DEFAULTS, ...userConfig };
    // If userConfig has __proto__, it pollutes the prototype
}
```

### Server-Side: Admin Check Bypass

```javascript
// 🔴 VULNERABLE: prototype pollution bypasses auth check
function isAdmin(user) {
    if (user.role === 'admin') return true;
    return false;
}

// If prototype has admin: true → user.role is undefined → prototype.role is checked → all users are admin!
```

```javascript
// Example of server-side RCE via prototype pollution
// Pollute Object.prototype with shell property
// If the app uses template engines or eval, polluted properties can execute code

// Attack payload:
// {"__proto__":{"exec":"require('child_process').execSync('id')"}}
```