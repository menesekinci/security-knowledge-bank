# 🟡 TypeScript Type Safety Bypass

> **Severity:** 🟡 Medium–High
> **CWE:** CWE-704 (Incorrect Type Conversion), CWE-915 (Improperly Controlled Modification of Dynamically-Determined Object Attributes), CWE-843 (Type Confusion)
> **AI Generation Risk:** Very High — LLMs frequently emit `as any`, `@ts-ignore`, and unchecked casts to silence the compiler

---

## Vulnerability Explanation

TypeScript's type system is **compile-time only**. Once compiled to JavaScript, every `as`, `as any`, `as unknown as T`, and `// @ts-ignore` disappears entirely. This means:

- **Type annotations provide ZERO runtime protection**
- An attacker sending malformed JSON bypasses all compile-time type guarantees
- `any` disables type checking completely — the variable accepts any shape at runtime
- `as` casts lie to the compiler but do nothing at runtime — no validation, no coercion

### Real-World Impact

Type confusion vulnerabilities have led to **Remote Code Execution (RCE)** in production systems. The most prominent example is **n8n's CVE-2026-25049** (CVSS 9.4, Critical), where the security of the entire expression evaluation engine rested on the TypeScript type annotation `input: string` — which vanishes at runtime. An attacker simply sent an **object instead of a string**, bypassing all string sanitization logic and achieving full RCE:

- **CVE-2026-25049 (n8n, CVSS 9.4):** TypeScript type annotation `function sanitize(input: string)` was the *only* defense against expression injection. At runtime, JavaScript accepted any type. Sending an object instead of a string skipped the sanitizer entirely. ([NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-25049), [Analysis](https://hetmehta.com/posts/n8n-type-confusion-rce/))
- **CVE-2025-68613 (n8n, CVSS 9.9):** Original expression injection via sandbox escape — the patch for this CVE was what CVE-2026-25049 bypassed via type confusion. ([NVD](https://nvd.nist.gov/vuln/detail/CVE-2025-68613), [Resecurity](https://www.resecurity.com/blog/article/cve-2025-68613-remote-code-execution-via-expression-injection-in-n8n-2))

The pattern is always the same: a developer assumes `input: string` guarantees input is a string, but an attacker sends `{ "constructor": { "prototype": { "isAdmin": true } } }` and the sanitization function never fires on non-string types.

---

## How AI / Vibe Coding Generates This

LLMs are optimized to make code compile. When TypeScript complains, the easiest fix the model can emit is:

```typescript
// @ts-ignore  ← AI's favorite shortcut
// as any      ← AI's second favorite
// as T        ← lies to compiler, no runtime check
```

Common AI-generated patterns:

| Pattern | What AI Does | Why It's Dangerous |
|---------|-------------|-------------------|
| `as any` on API response | Silences type error, assumes shape | No runtime validation of external data |
| `// @ts-ignore` above complex generic | Makes build pass | Hides real type mismatches |
| `as User` on `JSON.parse()` result | Tells compiler "trust me" | User is never validated at runtime |
| `any` in function params | Quick fix for "no overload matches" | Callers can pass anything |
| Non-null assertion `user!.name` | Suppresses `undefined` | Crashes if value is actually null/undefined |

---

## Vulnerable Code Examples + Secure Code Fix

### 1. `as any` — Complete Type Escape

```typescript
// 💀 VULNERABLE — Completely bypasses type safety:
function processInput(input: any) {
    // input can be anything!
    return input.toLowerCase();  // Crashes if a number comes in at runtime!
}

// ✅ SECURE — Type guard kullan:
function processInput(input: unknown) {
    if (typeof input === 'string') {
        return input.toLowerCase();
    }
    throw new Error('Expected string');
}
```

### 2. `// @ts-ignore` — Silences Real Errors

```typescript
// 💀 The AI's "quick fix":
// @ts-ignore
const result: string = await api.getData();  // Type checking completely skipped!
// api.getData() actually returned a number → runtime error!

// ✅ The right way: fix the type error, don't ignore it
const result = await api.getData();  // With type inference
```

### 3. `as` Cast — No Runtime Protection

```typescript
// 💀 What the AI wrote:
const user = data as User;  // Compile time only!
// data may actually be null or have a different shape

// ✅ Runtime validation:
function isUser(data: unknown): data is User {
    return typeof data === 'object' && data !== null && 'id' in data;
}

if (isUser(data)) {
    // Here data has type User
    console.log(data.id);
}
```

### 4. API Response Without Runtime Validation (Auth Bypass Scenario)

```typescript
// 💀 VULNERABLE — Auth bypass risk
async function getUser(req: Request): Promise<User> {
    const token = req.headers.authorization;
    const decoded = jwt.verify(token, SECRET) as User;  // as cast — no runtime check!
    // If JWT payload has extra fields like { id: 1, role: 'admin', isAdmin: true }
    // all are trusted blindly
    return decoded;
}

// ✅ SECURE — Zod runtime validation
import { z } from 'zod';

const UserSchema = z.object({
    id: z.number(),
    email: z.string().email(),
    role: z.enum(['user', 'admin']),
});

type User = z.infer<typeof UserSchema>;

async function getUser(req: Request): Promise<User> {
    const token = req.headers.authorization;
    const decoded = jwt.verify(token, SECRET);
    return UserSchema.parse(decoded);  // Strips unknown fields, validates types at runtime
}
```

### 5. Function Constructor / Sandbox Escape (n8n-style attack)

```typescript
// 💀 VULNERABLE — TypeScript type annotation is the ONLY defense
function evaluateExpression(input: string): any {
    // TypeScript says input must be string, but at runtime:
    // eval() accepts ANY type!
    return eval(input);
}

// Attacker sends: { "constructor": { "prototype": { ... } } }
// Sanitizer expects string, never executes on objects → TYPE CONFUSION → RCE

// ✅ SECURE — Runtime type check + sandbox
function evaluateExpression(input: unknown): any {
    if (typeof input !== 'string') {
        throw new Error('Expression must be a string');
    }
    // Additional: use vm.runInNewContext() instead of eval()
    // Apply allowlist-based sanitization
    return safeEvaluate(input);
}
```

### 6. JSON.parse + as Cast — The Most Common Pattern

```typescript
// 💀 VULNERABLE — 99% of AI-generated code does this
const config = JSON.parse(fs.readFileSync('config.json', 'utf-8')) as AppConfig;
// config can be anything at runtime — the 'as' does nothing

// ✅ SECURE — Zod parse
import { z } from 'zod';

const AppConfigSchema = z.object({
    port: z.number().int().positive().max(65535),
    host: z.string(),
    dbUrl: z.string().url(),
    jwtSecret: z.string().min(32),
});

const config = AppConfigSchema.parse(
    JSON.parse(fs.readFileSync('config.json', 'utf-8'))
);
// Throws with clear error if shape is wrong
```

---

## Prevention Checklist (Zod / Runtime Validation Integration)

- [ ] **Enable `strict: true`** in `tsconfig.json` — enables `noImplicitAny`, `strictNullChecks`, `strictFunctionTypes`
- [ ] **Ban `any`** — Use `eslint` rule `@typescript-eslint/no-explicit-any: error`. Use `unknown` instead and narrow with type guards
- [ ] **Ban `// @ts-ignore`** — Use `@typescript-eslint/ban-ts-comment: error`. Use `// @ts-expect-error` with a reason only when absolutely necessary
- [ ] **Use Zod (or io-ts, valibot) for ALL external data** — Every API response, JSON.parse, form submission, config file must pass a runtime schema validator
- [ ] **Ban `as` casts on external data** — Never use `JSON.parse(x) as T`. Always parse through a schema validator
- [ ] **Never use `as` for auth/user data** — JWT payloads, session data, and user objects must be validated with runtime schemas
- [ ] **Use branded types** for IDs and tokens to prevent type confusion between strings that represent different domains
- [ ] **Add pre-commit hooks** — `lint-staged` + `eslint` catches type escapes before they reach CI
- [ ] **Audit `// @ts-expect-error`** — Review every suppression in code review; most can be eliminated with proper generics
- [ ] **Runtime type guards for critical paths** — Use TypeScript's `x is T` return type for reusable validation functions

---

## Real CVEs / Case Refs

| CVE | Product | Score | Type | Description | Source |
|-----|---------|-------|------|-------------|--------|
| CVE-2026-25049 | n8n | 9.4 CRITICAL | Type Confusion → RCE | TypeScript `input: string` annotation used as sole security boundary. Object input bypassed sanitizer entirely, leading to sandbox escape and arbitrary code execution. Bypassed a fix for CVE-2025-68613. | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-25049), [Analysis](https://hetmehta.com/posts/n8n-type-confusion-rce/), [Endor Labs](https://www.endorlabs.com/learn/cve-2026-25049-n8n-rce) |
| CVE-2025-68613 | n8n | 9.9 CRITICAL | Expression Injection → RCE | Server-side expression evaluation sandbox escape. JavaScript expressions in `{{ }}` blocks could access `this` — the Node.js global object — and execute `require('child_process').execSync()`. | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2025-68613), [Resecurity](https://www.resecurity.com/blog/article/cve-2025-68613-remote-code-execution-via-expression-injection-in-n8n-2), [CVE.org](https://www.cve.org/CVERecord?id=CVE-2025-68613) |

### Why These Matter for TypeScript Developers

The n8n CVEs are a **direct warning** to every TypeScript developer: treating the type system as a security boundary is dangerous. The original CVE-2025-68613 was patched by adding sanitization to the string-based expression input. The type annotation `input: string` gave developers a false sense of security. At runtime, JavaScript cheerfully accepted `{constructor: {prototype: {isAdmin: true}}}` — an object, not a string — and the sanitizer that only ran on strings was skipped entirely.

**Lesson:** TypeScript's type system is a developer tool, not a security control. Every security-critical boundary requires **runtime** enforcement.

---

## Vibe-Coding Red Flags

- `as any` in API response handlers — especially on `fetch()` or `axios` responses
- `// @ts-ignore` or `// @ts-expect-error` used to silence array/object access complaints
- `JSON.parse(x) as T` pattern — 100% of AI code generators emit this
- Functions typed as accepting `any` that are called with untrusted user input
- No Zod/io-ts/class-validator schemas in projects that handle external data
- Non-null assertions (`!`) used as a substitute for actual null checking
- Type-only DTOs (`interface` or `type`) used for request bodies without runtime validation
- `as` casts in the same file as `document.cookie`, `localStorage`, or `fetch()` — indicates data is being trusted without validation
- Importing a Zod/valibot schema but never calling `.parse()` — common in AI boilerplate

---

## Prevention (Summary)

- Use `unknown` instead of `any`
- Do not use `// @ts-ignore`
- Use type guards / validation instead of `as` casts
- Configure TS with `strict: true`
- Use runtime validation libraries such as Zod / io-ts
- Validate all external data (API response, JSON.parse, config) with a schema

---

**Severity: 🟡 Medium–High** — Runtime errors, loss of type safety, auth bypass, potential RCE.
