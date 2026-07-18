# Prototype Pollution — JavaScript

> **Severity:** Critical
> **CVSS:** 8.2–9.8 (High–Critical)
> **AI Generation Risk:** High — AI models write object merge/clone operations without security awareness

---

## Vulnerability Explanation

Prototype pollution is a JavaScript-specific vulnerability where an attacker manipulates the `__proto__`, `constructor.prototype`, or `prototype` property of an object to inject properties into the global `Object.prototype`. Since all JavaScript objects inherit from `Object.prototype`, a polluter property becomes available on **every object** in the runtime — including server configuration objects, security check objects, and DOM elements.

### The JavaScript Prototype Chain

```
myObject → Object.prototype → null
```

Every object lookup traverses this chain. If you set `Object.prototype.isAdmin = true`, then `({}).isAdmin` returns `true` — even though the object never had that property.

### How Prototype Pollution Works

```javascript
// A vulnerable merge function
function merge(target, source) {
  for (const key in source) {
    if (source.hasOwnProperty(key)) {
      if (isObject(source[key])) {
        if (!target[key]) target[key] = {};
        merge(target[key], source[key]);
      } else {
        target[key] = source[key];
      }
    }
  }
}

// Attacker sends: JSON.parse('{"__proto__": {"isAdmin": true}}')
const userInput = JSON.parse('{"__proto__": {"isAdmin": true}}');
merge({}, userInput);

// Now every object has isAdmin = true
console.log({}.isAdmin);  // true — 💥 Admin privileges for everyone!
```

### The Three Pollution Vectors

| Vector | Example | Defense |
|---|---|---|
| `__proto__` | `{__proto__: {polluted: true}}` | JSON schema validation |
| `constructor.prototype` | `{constructor: {prototype: {polluted: true}}}` | Safe merge libraries |
| `prototype` (via named key) | `Object.prototype` direct access | Object.freeze() |

---

## How AI / Vibe Coding Generates This

### 1. Recursive Object Merge (The #1 Source)

```javascript
// 🚫 VULNERABLE — AI-generated deep merge
function deepMerge(target, source) {
  for (const key in source) {
    if (source[key] && typeof source[key] === 'object') {
      if (!target[key]) target[key] = {};
      deepMerge(target[key], source[key]);  // 💥 No __proto__ check!
    } else {
      target[key] = source[key];  // 💥 Direct assignment
    }
  }
  return target;
}

// Used in config merging, state management, API response handling
app.use((req, res, next) => {
  // Merges user config into app config
  req.config = deepMerge(defaultConfig, req.body);  // 💥 Prototype pollution
  next();
});
```

### 2. Spread Operator in Nested Objects

```javascript
// 🚫 VULNERABLE — AI-generated config merger
const config = { ...defaults, ...userInput };  // ⚠️ Only pollutes if userInput has __proto__ directly
// But if userInput is parsed from JSON: JSON.parse('{"__proto__":{"isAdmin":true}}')
// The spread IS vulnerable to prototype pollution
```

### 3. Object.assign() with Nested Objects

```javascript
// 🚫 VULNERABLE — AI-generated settings merger
function applySettings(newSettings) {
  // Object.assign is NOT recursive, but __proto__ at top level still pollutes
  Object.assign(globalConfig, newSettings);  // 💥 If newSettings.__proto__ is set
}
```

### 4. URL Query String to Object Conversion

```javascript
// 🚫 VULNERABLE — AI-generated query parser
function parseQueryString(query) {
  const result = {};
  query.split('&').forEach(pair => {
    const [key, value] = pair.split('=');
    // Attacker sends: __proto__[isAdmin]=true
    // This sets result.__proto__.isAdmin = "true"
    setNestedValue(result, key, decodeURIComponent(value));  // 💥
  });
  return result;
}
```

### 5. Express Body Parser with Merge

```javascript
// 🚫 VULNERABLE — AI-generated Express middleware
const express = require('express');
const app = express();

app.use(express.json());  // Parses JSON body

app.post('/update-config', (req, res) => {
  // If req.body contains {"__proto__": {"admin": true}}
  mergeConfig(app.config, req.body);  // 💥 Global prototype pollution
  res.send('OK');
});
```

### 6. Lodash merge() (Historical — CVE-2018-3721)

```javascript
// 🚫 VULNERABLE — AI-generated code using Lodash merge
const _ = require('lodash');

function mergeUserConfig(userConfig) {
  // Lodash _.merge was vulnerable before 4.17.5
  _.merge(defaultConfig, userConfig);  // 💥 Prototype pollution via __proto__
}
// Fixed in lodash@4.17.5+ — but AI may generate old versions
```

### Why AI Does This

- **`deepMerge` is a common interview question:** AI training data is full of recursive merge implementations
- **`Object.assign` and spread are idiomatic:** AI uses them constantly without security awareness
- **Config merging is ubiquitous:** AI config management code always merges user input with defaults
- **No understanding of `__proto__` as a special key:** AI treats it as a regular property name
- **JSON parsing is assumed safe:** AI doesn't know that `JSON.parse` preserves `__proto__` keys

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

## Secure Code Fix

### Fix 1: Safe Merge Without __proto__

```javascript
// ✅ SAFE — Explicit __proto__ check in merge
function safeMerge(target, source) {
  // Reject prototype pollution keys
  const BLACKLISTED_KEYS = ['__proto__', 'constructor', 'prototype'];
  
  for (const key in source) {
    if (source.hasOwnProperty(key)) {
      if (BLACKLISTED_KEYS.includes(key)) {
        continue;  // Skip dangerous keys
      }
      
      if (typeof source[key] === 'object' && source[key] !== null) {
        if (!target[key]) target[key] = {};
        safeMerge(target[key], source[key]);
      } else {
        target[key] = source[key];
      }
    }
  }
  return target;
}
```

### Fix 2: Use Object.create(null) for Untrusted Keys

```javascript
// ✅ SAFE — Objects without prototype chain
const safeMap = Object.create(null);  // No __proto__, no prototype chain
safeMap['__proto__'] = 'value';       // Safe — just a regular property
console.log(safeMap['__proto__']);    // 'value' — no pollution
console.log(safeMap.isAdmin);         // undefined — no inheritance
```

### Fix 3: Use Safe Libraries

```javascript
// ✅ SAFE — Use lodash with fixed version
const _ = require('lodash');
// lodash >= 4.17.12 is safe (4.17.5 fixed _.merge; 4.17.12 also fixed _.defaultsDeep — CVE-2019-10744)
_.merge(defaultConfig, userInput);  // ✅ Has __proto__ protection

// Or use deepmerge library (built for this)
const deepmerge = require('deepmerge');
const config = deepmerge(defaults, userInput);  // ✅ Protects against pollution
```

### Fix 4: Freeze Object.prototype

```javascript
// ✅ SAFE — Prevent prototype mutation entirely
Object.freeze(Object.prototype);
// This prevents __proto__ assignment across the entire runtime
```

### Fix 5: JSON Schema Validation

```javascript
// ✅ SAFE — Validate JSON input against schema
const Ajv = require('ajv');
const ajv = new Ajv();

const configSchema = {
  type: 'object',
  properties: {
    port: { type: 'integer', minimum: 1024, maximum: 65535 },
    features: {
      type: 'object',
      properties: {
        darkMode: { type: 'boolean' }
      },
      additionalProperties: false  // No extra keys
    }
  },
  additionalProperties: false  // Rejects __proto__, constructor, etc.
};

app.post('/update', (req, res) => {
  const validate = ajv.compile(configSchema);
  if (!validate(req.body)) {
    return res.status(400).json({ error: 'Invalid config' });
  }
  // Safe to merge now — schema rejected dangerous keys
  safeMerge(defaultConfig, req.body);
});
```

### Fix 6: Use Map Instead of Plain Objects

```javascript
// ✅ SAFE — Map has no prototype pollution vector
const config = new Map();
config.set('__proto__', 'value');  // Safe — Map keys are separate from prototype
console.log(config.get('__proto__'));  // 'value'
console.log(config.isAdmin);           // undefined
```

---

## Prevention Checklist

- [ ] NEVER write recursive merge functions without `__proto__` / `constructor.prototype` checks
- [ ] Use `Object.create(null)` for dictionaries/maps that accept user keys
- [ ] Use safe merge libraries: `lodash@>=4.17.12`, `deepmerge`, `just-safe-set`
- [ ] Validate JSON inputs against a strict schema before processing
- [ ] Freeze `Object.prototype` in security-critical Node.js apps
- [ ] Use `Map` objects instead of plain objects for dynamic key storage
- [ ] Sanitize query string parsers to reject `__proto__` keys
- [ ] In Express, use `express.json()` with `bodyParser.json({ strict: true })`
- [ ] Apply `Object.freeze(Object.prototype)` in production initialization
- [ ] Audit all AI-generated code for `merge`, `assign`, `spread`, and `__proto__` usage

---

## Real-World CVEs

| CVE | Description | Impact |
|---|---|---|
| **CVE-2024-29650** | Prototype pollution in popular JS library (2024) | Affected multiple downstream apps |
| **CVE-2023-26136** | `tough-cookie` < 4.1.3 — pollution via `CookieJar` in `rejectPublicSuffixes=false` mode | Prototype pollution (CVSS 9.8) |
| **CVE-2022-46175** | `json5` — `parse()` fails to block `__proto__` keys (< 1.0.2, 2.0.0–2.2.1) | Prototype pollution → DoS/XSS/RCE (CVSS 8.8) |
| **CVE-2021-3918** | `json-schema` <= 0.3.0 prototype pollution | Widely bundled; affected many downstream deps (CVSS 9.8) |
| **CVE-2020-8203** | `lodash` < 4.17.20 — pollution via `_.zipObjectDeep` | Prototype pollution → DoS/RCE (CVSS 7.4) |
| **CVE-2020-28273** | `set-in` 1.0.0–2.0.0 — property setter prototype pollution | DoS, potentially RCE (CVSS 9.8) |
| **CVE-2019-10744** | `lodash.merge` / `_.defaultsDeep` prototype pollution | Affected all lodash versions before 4.17.12 |
| **CVE-2018-3721** | lodash `_.merge` / `_.defaultsDeep` (< 4.17.5) | Original lodash pollution CVE |

### Real-World Exploitation

Prototype pollution has been exploited in the wild to:

- **Bypass authentication** — Pollute `isAdmin`, `authenticated`, `role` properties
- **Bypass authorization** — Pollute `canDelete`, `canEdit` permission checks
- **Inject XSS** — Pollute DOM element properties that map to event handlers
- **Bypass sanitization** — Pollute validation library configs
- **Defeat CSP** — Pollute CSP configuration objects

---

## Vibe Coding Red Flags

In AI-generated JavaScript, flag these immediately:

```javascript
function merge(target, source) { ... }       // 💥 Custom merge without safety
function deepMerge(target, source) { ... }   // 💥 Custom deep merge
function extend(target, source) { ... }      // 💥 jQuery-style extend
Object.assign(target, source)                // ⚠️ If source has __proto__
{ ...defaults, ...userInput }                // ⚠️ If userInput has __proto__
_.merge(target, source)                      // ⚠️ Check lodash version
_.defaultsDeep(target, source)               // ⚠️ Check lodash version
```

> **Golden Rule:** Any function that recursively copies properties from user input onto an object is a prototype pollution vulnerability until proven otherwise. Use libraries specifically designed for safe merging, never custom implementations.
