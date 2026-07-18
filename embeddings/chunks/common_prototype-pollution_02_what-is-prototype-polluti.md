---
source: "common/prototype-pollution.md"
title: "Prototype Pollution"
heading: "What Is Prototype Pollution?"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [checklist, code, common-vuln, fixed, prevention, vibe, vulnerable, what]
chunk: 2/8
---

## What Is Prototype Pollution?

Prototype pollution is a JavaScript-specific vulnerability where an attacker **injects properties into an object's prototype chain** (`Object.prototype`, `Array.prototype`). Since all objects inherit from these prototypes, polluting them affects **every object** in the application — including server-side objects.

**The impact:** 
- **Client-side:** DOM manipulation, XSS, filter bypass
- **Server-side (Node.js):** Remote code execution, privilege escalation, authentication bypass, denial of service