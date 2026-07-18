---
source: "common/secure-code-review.md"
title: "🔍 Secure Code Review Checklist"
heading: "2. Red Flags (Immediate Blockers)"
category: "common-vuln"
language: "common"
severity: "medium"
tags: [ai-generated, automated, common-vuln, flags, language-specific, review, reviewing, security]
chunk: 3/8
---

## 2. Red Flags (Immediate Blockers)

These findings require immediate rejection of the code — DO NOT merge until fixed:

### 🚨 CRITICAL (Fix Immediately — Block Merge)

- [ ] **Hardcoded credentials**: API keys, passwords, tokens, or secrets in source code
- [ ] **Code injection**: `eval()`, `exec()`, `compile()`, `Expression()` in any language
- [ ] **OS command injection**: Shell calls with unsanitized input (`os.system()`, `subprocess(shell=True)`)
- [ ] **SQL injection**: String concatenation in queries instead of parameterized queries
- [ ] **Insecure deserialization**: `pickle.load()`, `YAML.load()`, `BinaryFormatter`, `ObjectInputStream.readObject()`
- [ ] **Authentication bypass**: JWT with `alg: none`, any hardcoded admin check
- [ ] **Unrestricted file upload**: Allowing arbitrary file types without validation
- [ ] **Disabled security features**: `verify=False` (SSL), `protect_from_forgery except:`, `csrf_exempt`
- [ ] **Mass assignment**: `params.permit!`, `Model.create(request.body)`, `set_attributes(params)`
- [ ] **Path traversal**: User input in file paths without canonical path validation

### 🔴 HIGH (Must Fix Before Merge)

- [ ] **XSS**: Unsanitized user input rendered as HTML (`innerHTML`, `dangerouslySetInnerHTML`)
- [ ] **SSTI**: User input in template expression (Jinja2, ERB, Pug, etc.)
- [ ] **SSRF**: User-controlled URLs fetched by server
- [ ] **IDOR**: Object access without ownership check
- [ ] **Missing authorization**: API endpoints without auth checks
- [ ] **CORS misconfiguration**: `Access-Control-Allow-Origin: *` with credentials
- [ ] **Insecure redirect**: `redirect(params[:url])` without validation
- [ ] **Weak crypto**: MD5, SHA1, DES, ECB mode, hardcoded IV/password
- [ ] **Format string vulnerability**: `printf(user_input)` (C/C++)
- [ ] **Type confusion**: `as any` / `// @ts-ignore` / `!` non-null bypass (TypeScript)
- [ ] **Unsafe unwrap**: `!!` forced unwrap without check (Swift/Kotlin)
- [ ] **`tx.origin` usage**: Solidity authentication (use `msg.sender` instead)

### 🟡 MEDIUM (Should Fix, May Merge with Tracking Issue)

- [ ] **Verbose error messages**: Stack traces exposed to end users
- [ ] **Missing rate limiting**: APIs vulnerable to brute force/enumeration
- [ ] **Missing security headers**: CSP, HSTS, X-Frame-Options, X-Content-Type-Options
- [ ] **Logging sensitive data**: Passwords, tokens, PII in application logs
- [ ] **Insufficient input validation**: Missing type, length, or format validation
- [ ] **Hardcoded test data**: Test records or test credentials usable in production
- [ ] **Outdated dependencies**: Known vulnerable library versions
- [ ] **Weak session management**: No session timeout, predictable session tokens
- [ ] **Insecure defaults**: Debug mode enabled, default admin accounts
- [ ] **Missing CSRF tokens**: State-changing requests without CSRF protection

---