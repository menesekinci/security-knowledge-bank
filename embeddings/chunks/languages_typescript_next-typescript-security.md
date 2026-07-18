---
source: "languages/typescript/next-typescript-security.md"
title: "Next.js + TypeScript Security"
category: "language-vuln"
language: "typescript"
severity: "critical"
tags: [code, explanation, focus, language-vuln, secure, typescript, vulnerability, vulnerable]
---

# Next.js + TypeScript Security

> **Severity:** Critical (middleware/auth classes)
> **CWE:** CWE-287, CWE-863, CWE-79
> **AI Generation Risk:** Very High — AI trusts types and middleware as security boundaries

---

## Vulnerability Explanation

TypeScript + Next.js is the default vibe-coding stack. Types **erase at runtime**. Next.js adds:

1. **Middleware auth** that can be bypassed if mis-trusted (see CVE-2025-29927)
2. **Server Actions / Route Handlers** with weak validation
3. **RSC serialization** leaking secrets into client payloads
4. **`as User` casts** after `fetch` without Zod parse

---

## How AI / Vibe Coding Generates This

```ts
// AI: "protect dashboard"
export function middleware(req: NextRequest) {
  if (!req.cookies.get('session')) {
    return NextResponse.redirect('/login');
  }
}
// assumes middleware always runs — must still authorize in handlers
```

```ts
const body = (await req.json()) as CreateOrderDto; // trust boundary broken
```

---

## Vulnerable Code Example

```typescript
// app/api/admin/route.ts
export async function GET(req: Request) {
  // middleware "already checked" — still IDOR / direct hit risks
  return Response.json(await db.users.findMany());
}
```

Server Action without authz:

```typescript
'use server'
export async function deleteUser(id: string) {
  await db.user.delete({ where: { id } });
}
```

---

## Secure Code Fix

```typescript
import { z } from 'zod';

const OrderSchema = z.object({
  productId: z.string().uuid(),
  qty: z.number().int().positive().max(99),
});

export async function POST(req: Request) {
  const session = await requireSession(); // throws if missing
  const parsed = OrderSchema.safeParse(await req.json());
  if (!parsed.success) return new Response('bad', { status: 400 });
  await createOrder(session.userId, parsed.data);
  return Response.json({ ok: true });
}
```

Defense in depth:

- AuthN/AuthZ in **every** Server Action / Route Handler (middleware is not enough)
- Runtime validation (Zod) for all external input
- Patch Next.js promptly (middleware bypass class)
- Never put secrets in `NEXT_PUBLIC_*`
- CSP + careful `dangerouslySetInnerHTML`

---

## CVE focus (verified)

| CVE | Issue | Ref |
|-----|--------|-----|
| **CVE-2025-29927** | Next.js middleware authorization bypass via crafted `x-middleware-subrequest` handling | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2025-29927), [Datadog analysis](https://securitylabs.datadoghq.com/articles/nextjs-middleware-auth-bypass/) |
| Related ecosystem | React/Next RCE classes tracked under separate CVEs — keep framework updated | Vercel / GitHub advisories |

Patched lines (advisory): upgrade to vendor-fixed 12.3.5 / 13.5.9 / 14.2.25 / 15.2.3 or later per your major.

---

## Prevention Checklist

- [ ] Next.js on patched version (CVE-2025-29927+)
- [ ] Authorization in handlers, not only middleware
- [ ] Zod (or equal) on body/query
- [ ] No secrets in client bundles
- [ ] Security headers / CSP
- [ ] Semgrep: `vibe-typescript.yml` + `vibe-javascript.yml`

---

## Vibe-Coding Red Flags

- "`as User` after fetch"
- Middleware-only security
- Server Actions without `requireUser()`
- Ignoring framework security advisories because "types pass"
'''