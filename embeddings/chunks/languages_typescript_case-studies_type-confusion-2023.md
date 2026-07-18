---
source: "languages/typescript/case-studies/type-confusion-2023.md"
title: "TypeScript — Type Assertion & Missing Runtime Validation (Illustrative Case Study)"
category: "case-study"
language: "typescript"
severity: "critical"
tags: [case-study, cause, impact, learned, lessons, pattern, potential, root, this, typescript]
---

# TypeScript — Type Assertion & Missing Runtime Validation (Illustrative Case Study)

> **Note:** This is a **hypothetical, illustrative example**, not a report of a specific
> named incident. It demonstrates a real and common class of TypeScript vulnerability —
> trusting compile-time types at runtime — using invented code. No real company,
> researcher, or CVE is described here.

## 🎯 What This Illustrates
How a TypeScript backend can be compromised when developers treat the type system as a
runtime guarantee. The type checker is erased at compile time, so `any`, `as` casts, and
the non-null assertion (`!`) provide **zero** protection against malformed input.

## 🔴 The Pattern

A common shape of this bug:

- A handler declares a parameter as `string` (or casts input with `as string`), but the
  value actually arrives as an **object or array** (e.g. from a query string like
  `?userId[]=1&userId[]=2`, which many parsers turn into an array).
- Because TypeScript types don't exist at runtime, no error is thrown at the boundary.
- The unexpected type flows into authorization checks, database lookups, or URL building,
  producing an **IDOR (Insecure Direct Object Reference)**, a broken auth check, or a
  malformed downstream request.

## 🧠 Root Cause

```typescript
// 💀 VULNERABLE: type says string, runtime says "whatever the client sent"
async function getUserData(userId: any) {   // `any` disables all checking
    // If userId arrives as an array (?userId[]=1&userId[]=2) or object,
    // it is NOT a string at runtime. Interpolating it produces a
    // malformed/unexpected request (e.g. "[object Object]" or "1,2"),
    // which can bypass an ownership check or hit the wrong record — an IDOR.
    const response = await fetch(`/api/users/${userId}`);
    return response.json();
}

// ✅ CORRECT: validate the runtime shape at the trust boundary
async function getUserData(userId: unknown) {
    if (typeof userId !== 'string' || !isValidUUID(userId)) {
        throw new Error('Invalid user ID');
    }
    // now userId is provably a string at runtime
    const response = await fetch(`/api/users/${encodeURIComponent(userId)}`);
    return response.json();
}
```

> **Important:** interpolating an object/array into a URL like this is **not** SQL
> injection — it is a type-confusion / IDOR / request-smuggling risk. SQL injection is a
> separate issue that arises only when unvalidated input is concatenated into a SQL query.
> Both share the same root cause: trusting a type that was never checked at runtime.

## 💥 Potential Impact
- **IDOR / broken authorization**: an unexpected type slips past an ownership or role check.
- **Data exposure**: the wrong record is fetched and returned to the caller.
- **Downstream errors**: malformed requests to internal services, cache poisoning, crashes.

## 🎓 Lessons Learned
- **TypeScript type safety is compile-time only**: at runtime, `any`, `as`, and `!` do not protect you.
- **Runtime validation is essential**: validate every external input with a schema library (Zod, io-ts, yup, valibot).
- **Avoid `any`**: use `unknown` plus a type guard when the type is genuinely uncertain.
- **Validate at the API layer**: never assume the request parser gave you the declared type.

## Vibe Coding Connection
When AI produces TypeScript code:
- AI frequently silences type errors with `as` casts and `any` instead of validating.
- Add "add runtime validation for all external input" to your prompt.
- Require Zod/io-ts (or similar) at every trust boundary.

## 🔗 Further Reading
- Zod — runtime schema validation for TypeScript: https://zod.dev/
- OWASP — Insecure Direct Object Reference (IDOR): https://owasp.org/www-project-top-ten/
- TypeScript Handbook — `unknown`, type guards, and narrowing: https://www.typescriptlang.org/docs/handbook/2/narrowing.html
