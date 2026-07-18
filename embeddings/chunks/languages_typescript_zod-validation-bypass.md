---
source: "languages/typescript/zod-validation-bypass.md"
title: "Zod / Runtime Validation Bypass"
category: "language-vuln"
language: "typescript"
severity: "high"
tags: [checklist, code, explanation, language-vuln, prevention, secure, typescript, vulnerability, vulnerable]
---

# Zod / Runtime Validation Bypass

> **Severity:** High
> **CWE:** CWE-20, CWE-704
> **AI Generation Risk:** Very High — TypeScript types treated as validation

---

## Vulnerability Explanation

Zod (and similar) close the **compile-time vs runtime** gap. Vibe coding fails when AI:

1. Defines Zod schemas but uses `as` cast instead of `.parse`
2. Uses `.passthrough()` / `.strip()` incorrectly and accepts attacker fields
3. Validates only partially (body but not query)
4. Trusts `z.infer<typeof Schema>` type after unvalidated `JSON.parse`

Types never execute. Schemas only help if **called**.

---

## How AI / Vibe Coding Generates This

```typescript
type User = z.infer<typeof UserSchema>;
const user = (await req.json()) as User; // schema never runs
```

```typescript
UserSchema.parse(req.body); // then ignores result and uses req.body
doWork(req.body);
```

---

## Vulnerable Code Example

```typescript
const PatchSchema = z.object({
  displayName: z.string().max(40),
}).passthrough(); // allows role, isAdmin, etc.

export async function PATCH(req: Request) {
  const data = PatchSchema.parse(await req.json());
  await db.user.update({ where: { id }, data }); // mass assignment
}
```

---

## Secure Code Fix

```typescript
const PatchSchema = z.object({
  displayName: z.string().min(1).max(40),
}).strict(); // reject unknown keys

export async function PATCH(req: Request) {
  const data = PatchSchema.parse(await req.json());
  await db.user.update({
    where: { id: session.userId },
    data: { displayName: data.displayName },
  });
}
```

Patterns:

- Prefer `.strict()` on external objects
- Use `safeParse` + explicit error mapping
- Never cast to `z.infer` without parse
- Separate **input DTO schemas** from **DB models**

---

## Prevention Checklist

- [ ] Every external boundary: HTTP, queue, webhook, CLI argv
- [ ] `.strict()` or explicit pick for patches
- [ ] No `as T` on untrusted JSON
- [ ] Unit tests for extra-field rejection
- [ ] OpenAPI/tRPC procedures use shared schemas

---

## Real-World References

| Ref | Notes |
|-----|--------|
| [Zod docs — strict objects](https://zod.dev/) | |
| Mass assignment class: [OWASP](https://owasp.org/www-community/vulnerabilities/Mass_Assignment_Cheat_Sheet) | |
| Next.js typed handlers still need runtime checks | |

---

## Vibe-Coding Red Flags

- Schema defined, never `.parse`'d
- `.passthrough()` on user patches
- `as z.infer<typeof X>` after `JSON.parse`
- "TypeScript already validates this"
'''