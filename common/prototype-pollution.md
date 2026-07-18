# Prototype Pollution

**CWE:** CWE-1321 (Improperly Controlled Modification of Object Prototype Attributes)
**OWASP Top 10:2021:** A08 — Software and Data Integrity Failures

---

## What Is Prototype Pollution?

Prototype pollution is a JavaScript-specific vulnerability where an attacker **injects properties into an object's prototype chain** (`Object.prototype`, `Array.prototype`). Since all objects inherit from these prototypes, polluting them affects **every object** in the application — including server-side objects.

**The impact:** 
- **Client-side:** DOM manipulation, XSS, filter bypass
- **Server-side (Node.js):** Remote code execution, privilege escalation, authentication bypass, denial of service

## Why Vibe Coding Makes This Worse

- **AI uses merge/clone operations:** `Object.assign()`, spread `{...obj}`, `_.merge()`, `$.extend()` are common AI patterns
- **AI doesn't validate `__proto__`:** Generated merge functions don't check for `__proto__`, `constructor.prototype`
- **AI uses unsafe npm packages:** Many merge libraries had prototype pollution vulnerabilities
- **AI-generated deep clone:** AI writes recursive clone without prototype pollution protection
- **AI generates config merging:** Deep merging user config with default config is a common AI pattern

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

## Fixed Code Examples

### Safe Merge Function

```javascript
// ✅ SAFE: prevent prototype pollution in merge
function safeMerge(target, source) {
    for (const key of Object.keys(source)) {
        // Skip dangerous keys
        if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
            continue;
        }

        if (typeof source[key] === 'object' && source[key] !== null) {
            if (!target[key]) target[key] = {};
            safeMerge(target[key], source[key]);
        } else {
            target[key] = source[key];
        }
    }
    return target;
}
```

### Use Object.create(null) for Maps/Dictionaries

```javascript
// ✅ SAFE: create objects with no prototype chain
const safeConfig = Object.create(null);  // No __proto__ at all
safeConfig.port = 3000;

// Merge into this safe object
Object.assign(safeConfig, JSON.parse(userInput));
// If userInput has __proto__, assign() modifies the __proto__
// but since safeConfig has no prototype, it's just a regular property
```

### Use Map Instead of Object

```javascript
// ✅ SAFE: Map is not vulnerable to prototype pollution
const config = new Map();
config.set('port', 3000);

const userInput = JSON.parse('{"__proto__": {"admin": true}}');
for (const [key, value] of Object.entries(userInput)) {
    config.set(key, value);  // Stored in Map, not on prototype
}
// config.get('admin') → true (as a key in the map, not as a prototype)
// But: {}.admin → undefined (prototype not polluted!)
```

### Safe Version Checking on Input

```javascript
// ✅ SAFE: strip dangerous keys before any merge
function sanitizeKeys(obj) {
    if (typeof obj !== 'object' || obj === null) return obj;

    const safe = {};
    for (const [key, value] of Object.entries(obj)) {
        if (key === '__proto__' || key === 'constructor') continue;
        safe[key] = sanitizeKeys(value);
    }
    return safe;
}

const cleanInput = sanitizeKeys(JSON.parse(userInput));
```

### Use Libraries That Are Prototype-Pollution Safe

```javascript
// ✅ SAFE: modern lodash (4.17.21+) is patched
const _ = require('lodash');
const result = _.defaultsDeep(userInput, defaults);  // Patched version

// ✅ SAFE: immer (immutable state)
const { produce } = require('immer');
const nextState = produce(baseState, draft => {
    // immer uses proxies, not direct property assignment
});
```

---

## Prevention Checklist for AI Prompts

```
✅ PROTOTYPE POLLUTION PREVENTION:
- Use Object.create(null) for dictionaries/maps that accept user input
- Use Map instead of plain objects for key-value storage
- Before merge/clone, check and reject keys named __proto__, constructor, prototype
- Use libraries that are patched against pollution (lodash >= 4.17.21, jQuery >= 3.5.0)
- Use Object.freeze(Object.prototype) in critical environments
- Never deep-merge untrusted user input into existing objects
- Use JSON Schema validation before processing user objects
- Sanitize all incoming JSON with key filtering
- Use immutable patterns (immer, immutable.js)
- Pin npm packages to versions with prototype pollution fixes
```

### NPM Package Security

| Package | Safe Version | Notes |
|---|---|---|
| lodash | >= 4.17.21 | CVE-2020-8203 (prototype pollution in `zipObjectDeep`) |
| jQuery | >= 3.4.0 | CVE-2019-11358 (prototype pollution in `$.extend`) |
| $.extend | >= 3.4.0 | Deep extend polluted `Object.prototype` before 3.4.0 |
| handlebars | >= 4.3.0 | CVE-2019-19919 (prototype pollution) |
| merge | >= 2.1.1 | npm merge package |
| immer | >= 8.0.1 | Doesn't allow prototype stuff |

---

## Real-World CVEs

| Vulnerability | CVE | Impact |
|---|---|---|
| lodash `defaultsDeep` prototype pollution | CVE-2019-10744 | `Object.prototype` pollution (CVSS 9.1) — integrity/availability impact |
| lodash `zipObjectDeep` prototype pollution | CVE-2020-8203 | `Object.prototype` pollution (CVSS 7.4) |
| json5 `parse()` prototype pollution | CVE-2022-46175 | Pollution via `__proto__` in parsed object → XSS/privesc/DoS |
| json-schema prototype pollution | CVE-2021-3918 | Prototype pollution (CVSS 9.8) |
| Kibana (Timelion) prototype pollution | CVE-2019-7609 | RCE — attacker could execute commands |

> **The Kibana case (CVE-2019-7609):** Attackers exploited prototype pollution in Kibana's Timelion visualizer to reach a code-evaluation path, achieving remote code execution on Elastic Stack deployments (CVSS 10.0).

---

## References

- [OWASP Prototype Pollution](https://owasp.org/www-community/attacks/Prototype_Pollution)
- [CWE-1321: Improperly Controlled Modification of Object Prototype Attributes](https://cwe.mitre.org/data/definitions/1321.html)
- [PortSwigger Prototype Pollution Guide](https://portswigger.net/web-security/prototype-pollution)
- [Snyk — Prototype Pollution Explained](https://snyk.io/blog/prototype-pollution-the-dangerous-vulnerability-in-javascript-applications/)
- [Detectify — SSRF via PDFKit](https://blog.detectify.com/2022/03/11/prototype-pollution-vulnerability-in-pdfkit-cve-2022-25772/)
