---
source: "languages/typescript/type-safety-bypass.md"
title: "🟡 TypeScript Type Safety Bypass"
heading: "Vulnerable Code Examples + Secure Code Fix"
category: "language-vuln"
language: "typescript"
severity: "medium"
tags: [checklist, code, cves, explanation, language-vuln, prevention, real, typescript, vulnerability, vulnerable]
chunk: 4/8
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