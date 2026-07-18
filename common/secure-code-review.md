# 🔍 Secure Code Review Checklist

> **Category:** Common / Secure Code Review
> **Last Updated:** July 2026
> **Description:** Security code review checklist with specific focus on what to look for when reviewing AI-generated code — red flags, automated tools, and proven review workflows.

---

## 1. The Security Code Review Process

```
┌──────────────────────────────────────────────────────────┐
│                SECURE CODE REVIEW FLOW                     │
├──────────────────────────────────────────────────────────┤
│                                                           │
│  PR CREATED                                               │
│     │                                                     │
│  1. AUTOMATED GATES                                       │
│     ├─ SAST (Semgrep, CodeQL, Brakeman, etc.)             │
│     ├─ Secret scan (Gitleaks, truffleHog)                 │
│     ├─ Dependency scan (Trivy, npm audit)                 │
│     └─ Linting + formatting                               │
│     │                                                     │
│  2. MANUAL REVIEW                                         │
│     ├─ Check the CHANGES, not the whole file              │
│     ├─ Focus on HIGH RISK areas                           │
│     │   ├─ Auth / authorization                           │
│     │   ├─ Data validation / sanitization                 │
│     │   ├─ Crypto / secrets                               │
│     │   ├─ Serialization / deserialization                │
│     │   ├─ SQL / query building                           │
│     │   ├─ File I/O / path handling                       │
│     │   └─ External integrations                          │
│     └─ Use checklist below                                │
│     │                                                     │
│  3. DECISION                                              │
│     ├─ Approve (no security concerns)                     │
│     ├─ Changes requested (fix security issues)            │
│     └─ Block (critical vulnerability)                     │
│                                                           │
└──────────────────────────────────────────────────────────┘
```

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

## 3. Automated Review Tools

### SAST Tools (Run in CI)

| Tool               | Languages              | Key Strengths                       |
|--------------------|------------------------|-------------------------------------|
| **Semgrep**        | 30+ languages          | Custom rules, high signal-to-noise  |
| **CodeQL**         | C/C++, C#, Go, Java, JS/TS, Python | Deep data flow analysis |
| **GitHub Code Scanning** | Multi-language   | Integrated with PR checks           |
| **SonarQube**      | 30+ languages          | Quality + security, tech debt       |
| **Brakeman**       | Ruby on Rails          | Rails-specific, low false positives |
| **Bandit**         | Python                 | Security-focused, simple rules      |
| **gosec**          | Go                     | Go-specific security patterns       |
| **Clippy**         | Rust                   | Lint + some security checks         |
| **detekt**         | Kotlin                 | Kotlin-specific static analysis     |
| **SecurityCodeScan**| C#                    | .NET security patterns              |
| **Slither**        | Solidity               | Smart contract vulnerabilities      |

### Secret Detection

| Tool                 | Scope             | CI Integration |
|----------------------|-------------------|----------------|
| **Gitleaks**         | Git history       | ✅ Pre-commit + CI |
| **truffleHog**       | Git + filesystem  | ✅ CI           |
| **GitHub Secret Scanning**| GitHub repos| ✅ Native       |
| **GitGuardian**      | API + CLI         | ✅ CI + Portal  |

### Dependency Scanners

| Tool                 | Scope              | CI Integration |
|----------------------|--------------------|----------------|
| **Trivy**            | All ecosystems     | ✅ Container + FS |
| **Snyk**             | Multi-language     | ✅ CI + CLI     |
| **npm audit**        | JS/TS              | ✅ CI           |
| **cargo audit**      | Rust               | ✅ CI           |
| **pip-audit**        | Python             | ✅ CI           |
| **govulncheck**      | Go                 | ✅ CI           |
| **OWASP Dependency-Check**| Java/.NET    | ✅ CI           |

### AI-Assisted Code Review Tools

| Tool                   | What It Does                                   |
|------------------------|------------------------------------------------|
| **GitHub Copilot Code Review** | AI-powered PR review suggestions     |
| **CodeRabbit**         | AI code review with security focus             |
| **SonarQube AI**       | AI-assisted issue detection                   |
| **Semgrep Pro**        | Interfile analysis + AI-powered prioritization |
| **Socket**             | AI-driven supply chain risk detection         |

---

## 4. Language-Specific Red Flags

### Python
| Red Flag | Risk | Fix |
|----------|------|-----|
| `eval()`, `exec()`, `compile(user_input)` | RCE, code injection | Use `ast.literal_eval()` or dedicated parser |
| `pickle.loads(user_data)` | Deserialization RCE | Use JSON or `safetensors` |
| `os.system(f"cmd {input}")` | Command injection | Use `subprocess.run()` with args list |
| `assert` for auth checks | Removed in optimized mode | Use proper auth middleware |
| `request.get_json()` without schema validation | Mass assignment | Use Pydantic/marshmallow schemas |

### JavaScript / TypeScript
| Red Flag | Risk | Fix |
|----------|------|-----|
| `eval(user_input)` | RCE, XSS | Never use eval |
| `innerHTML = user_input` | XSS | Use `textContent` or DOMPurify |
| `as any` / `any` type | Runtime type confusion | Use `unknown` + type guard |
| `// @ts-ignore` | Bypasses all type checks | Fix the type issue instead |
| `JSON.parse(user_input)` without validation | Prototype pollution | Use `JSON.parse` + schema validation (Zod) |

### Go
| Red Flag | Risk | Fix |
|----------|------|-----|
| `sql.DB.Query(fmt.Sprintf(...))` | SQL injection | Use parameterized queries |
| `http.Get(user_url)` | SSRF | Validate + restrict URL scheme |
| `ioutil.ReadAll(r.Body)` without limit | OOM | Use `http.MaxBytesReader` |
| `json.Unmarshal(data, &v)` without schema check | Type confusion | Validate after unmarshal |
| `crypto/md5` / `crypto/sha1` | Weak hash | Use `crypto/sha256` or `crypto/sha3` |

### Rust
| Red Flag | Risk | Fix |
|----------|------|-----|
| `unsafe` block without safety comment | Memory safety bypass | Document why and invariants |
| `unwrap()` on user input | Panic / DoS | Handle `Result` properly |
| `std::process::Command` with shell | Command injection | Use args list, not shell |
| `transmute()` without validation | Type confusion | Use safe conversions |
| `std::mem::zeroed()` | Undefined behavior | Use proper initialization |

### Ruby on Rails
| Red Flag | Risk | Fix |
|----------|------|-----|
| `params.permit!` | Mass assignment | Permit only expected fields |
| `where("name = '#{input}'")` | SQL injection | Use `where(name: input)` |
| `render inline: params[:template]` | RCE | Never render user input as inline |
| `skip_before_action :verify_authenticity_token` | CSRF | Verify token for state-changing requests |
| `File.open(user_filename)` | Path traversal | Validate + restrict to upload dir |

### Java / Kotlin
| Red Flag | Risk | Fix |
|----------|------|-----|
| `ObjectInputStream.readObject()` | Deserialization RCE | Use `ObjectInputFilter` or JSON |
| `Runtime.exec(input)` | Command injection | Use `ProcessBuilder` with args array |
| `@RequestMapping` without auth annotation | Missing authorization | Use `@PreAuthorize` or security config |
| `SpEL: #{user_input}` | Expression injection | Validate against allowlist |
| `String sql = "SELECT * FROM users WHERE id = " + id` | SQL injection | Use `PreparedStatement` |

### Solidity
| Red Flag | Risk | Fix |
|----------|------|-----|
| `tx.origin` for auth | Phishing attack | Use `msg.sender` |
| `call.value()` before state update | Reentrancy | Checks-Effects-Interactions pattern |
| `block.timestamp` for randomness | Manipulation | Use Chainlink VRF |
| `require()` without error message | Users can't diagnose | Add error string |
| Unbounded `for` loop | Gas DoS | Use pull-over-push pattern |

---

## 5. Reviewing AI-Generated Code: Specific Guidance

### AI Failure Patterns

| Pattern | What AI Does Wrong | How to Catch |
|---------|-------------------|--------------|
| **Hallucinated security** | AI writes `using System.Security.Cryptography;` but the implementation is completely broken | Verify the crypto code manually — does it actually do what it claims? |
| **Outdated patterns** | AI uses APIs from training cutoff (e.g., `create-react-app`, deprecated crypto) | Cross-reference with current docs |
| **Copy-pasted Stack Overflow** | Code snippet found online includes injection vulns | Search common vulnerable patterns (eval, exec, etc.) |
| **Missing edge cases** | AI handles happy path, forgets error states | Test with invalid inputs, boundary values |
| **Over-permissive defaults** | AI says "just allow all origins" for CORS | Check every config has a restrictive default |
| **Mock security** | AI writes auth that looks good but does nothing | Trace the auth flow — does it actually protect the resource? |
| **Fake libraries** | AI imports `python-jose` or `cryptography` badly | Verify the library API against official docs |

### Prompt-Level Review

Before reviewing AI code, check what the AI was asked to do:

- Was the prompt specific about security requirements?
- Did the prompt include examples of secure code?
- Was the task inherently dangerous (crypto, auth)?
- Did the AI have proper context (codebase, architecture)?

### AI Code Review Checklist (Additional)

- [ ] All third-party packages actually exist (check npm/PyPI/Crates.io)
- [ ] Security-related code is NOT AI-generated without human review
- [ ] AI-generated test code is reviewed as strictly as production code
- [ ] Error handling doesn't leak system information
- [ ] Configuration defaults are secure, not "just for testing"
- [ ] Rate limiting and throttling exist (AI rarely adds this)
- [ ] No `TODO: fix security later` left in code
- [ ] API key handling follows your organization's secret management policy

---

## 6. Quick Reference: Top 10 OWASP:2021 × AI Code

| OWASP Top 10 | AI Vulnerability Rate | What to Check |
|-------------|----------------------|---------------|
| **A01: Broken Access Control** | 🔴 High | AI often forgets authorization checks |
| **A02: Cryptographic Failures** | 🔴 High | AI uses outdated/weak crypto APIs |
| **A03: Injection** | 🔴 High | SQL, command, expression injection |
| **A04: Insecure Design** | 🟡 Medium | Missing rate limiting, business logic flaws |
| **A05: Security Misconfiguration** | 🟡 Medium | Debug mode, permissive CORS |
| **A06: Vulnerable Components** | 🔴 High | Hallucinated or outdated packages |
| **A07: Identification/Auth Failures** | 🔴 High | Weak password checks, session issues |
| **A08: Data Integrity Failures** | 🟢 Low | Deserialization in ML contexts |
| **A09: Logging/Monitoring** | 🟢 Low | No logging, verbose error messages |
| **A10: SSRF** | 🟡 Medium | User-controlled URLs fetched by server |

---

## References

- [OWASP Code Review Guide](https://owasp.org/www-project-code-review-guide/)
- [OWASP Top 10:2021](https://owasp.org/Top10/)
- [CWE Top 25](https://cwe.mitre.org/top25/)
- [Semgrep Registry — Security Rules](https://semgrep.dev/explore)
- [GitHub Security Lab](https://securitylab.github.com/tools/codeql)
- [Google AI Red Team](https://blog.google/technology/safety-security/ai-red-team/)
- [NIST Secure Software Development Framework (SSDF)](https://csrc.nist.gov/publications/detail/sp/800-218/final)
- [OWASP Mobile Security Testing Guide](https://owasp.org/www-project-mobile-security-testing-guide/)
