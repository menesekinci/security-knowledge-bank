# React/Next.js Deep Security — AI-Generated Code Edition

> **Severity:** Critical
> **CWE:** CWE-79 (XSS), CWE-94 (Code Injection), CWE-284 (Access Control), CWE-200 (Info Exposure), CWE-346 (CORS), CWE-502 (Deserialization), CWE-915 (Mass Assignment), CWE-918 (SSRF), CWE-863 (Incorrect Authorization)
> **AI Generation Risk:** Very High — AI treats framework boundaries as security boundaries

---

## 1. Vulnerability Explanation — How AI Generates React/Next.js Apps with Critical Flaws

AI coding assistants (Copilot, Claude, Cursor, etc.) are trained largely on public GitHub repositories that contain many vulnerable patterns. When prompted to "build a Next.js dashboard" or "add React authentication," AI models reproduce the most statistically common patterns — which frequently skip critical security controls. The result is **vibe-coded applications** that look functional but collapse under adversarial input.

### Server Components vs Client Components Confusion (Next.js 13+)

Next.js 13 introduced the App Router with React Server Components (RSC). The security model is radically different from traditional React:

| Aspect | Server Component | Client Component |
|--------|-----------------|-----------------|
| Runs on | Server only | Browser (and SSR) |
| Can access DB | Yes, directly | No |
| Secrets exposed | Never to client | Must use `NEXT_PUBLIC_` |
| Bundle size | Zero JS sent to client | Full JS sent to browser |
| `useState`, `useEffect` | **Not allowed** | Required |

**AI failure mode:** AI frequently marks entire pages or data-fetching components as `'use client'` unnecessarily, pushing sensitive logic — including database queries, API keys, and business rules — into the client bundle.

### AI Doesn't Understand RSC Security Boundaries

The RSC protocol (internally called "Flight") serializes component trees from server to client. AI models generate code that:

- Exposes server action endpoints without authentication checks
- Sends sensitive data in RSC payloads that are serialized to the client
- Calls `fetch()` inside client components to APIs that should be server-only
- Uses `dangerouslySetInnerHTML` on server-rendered content without sanitization

### AI Overuses 'use client'

The most common AI-generated antipattern:

```tsx
// AI writes this:
'use client';  // ← Unnecessary — this component doesn't use hooks!
import { db } from '@/lib/db';

export default function UserList() {
  const [users, setUsers] = useState([]);  // ← State on server component? No
  
  useEffect(() => {
    fetch('/api/users').then(r => r.json()).then(setUsers);
  }, []);
  
  return <div>{users.map(u => <p>{u.name}</p>)}</div>;
}
```

**Problems:** The `'use client'` directive sends all this code to the browser. If a developer mistakenly imports server-side modules (database clients, secret keys), they're shipped to every visitor.

### AI Generates Insecure Server Actions

```tsx
'use server';

// AI generation: "create a delete user function"
export async function deleteUser(userId: string) {
  // No authentication check!
  // No authorization check!
  await db.user.delete({ where: { id: userId } });
  revalidatePath('/users');
}
```

Any visitor can call this endpoint. No session check. No ownership verification.

---

## 2. How AI / Vibe Coding Generates These Vulnerabilities

### "Build a dashboard with Next.js" → No auth in server actions, data exposed via client

```tsx
// AI-generated dashboard (typical output from LLM):
import { db } from '@/lib/db';

export default async function AdminDashboard() {
  // AI assumes middleware handles auth
  // No server-side auth check here!
  const users = await db.user.findMany();  // Returns ALL users
  const payments = await db.payment.findMany();  // All payment data
  
  return (
    <div>
      <h1>Admin Dashboard</h1>
      <DataTable data={users} />  {/* Sensitive data in client component */}
      <RevenueChart data={payments} />
    </div>
  );
}
```

**Reality:** The middleware bypass vulnerability (CVE-2025-29927) proved that middleware is NOT a security boundary. Without auth checks inside the page/component itself, an attacker with a crafted header can access all this data.

### "Add file upload" → No file type validation, direct filesystem write

```tsx
'use server';
import { writeFile } from 'fs/promises';

// AI: "Add a file upload handler"
export async function uploadFile(formData: FormData) {
  const file = formData.get('file') as File;
  // No type validation! No size check! No virus scan!
  const bytes = await file.arrayBuffer();
  const buffer = Buffer.from(bytes);
  
  // Writes directly to public directory — accessible by anyone
  await writeFile(`public/uploads/${file.name}`, buffer);
  return { url: `/uploads/${file.name}` };
}
```

**Exploit:** Upload a `.html` file containing JavaScript → stored XSS. Upload a `.php` file → RCE if server processes it. Upload a symlink → arbitrary file read/write.

### "Admin panel" → No middleware protection, all routes public

```tsx
// AI generates layout for admin:
export default function AdminLayout({ children }: { children: React.ReactNode }) {
  return (
    <div>
      <Sidebar />
      <main>{children}</main>  {/* No auth wrapper! */}
    </div>
  );
}
```

### Middleware bypass patterns

```tsx
// middleware.ts — AI generates this as THE ONLY auth layer:
import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';

export function middleware(request: NextRequest) {
  const token = request.cookies.get('session');
  if (!token) {
    return NextResponse.redirect(new URL('/login', request.url));
  }
  // No token validation! Just checks existence
}

export const config = {
  matcher: ['/dashboard/:path*', '/admin/:path*'],
};
```

**Problem:** Middleware is the only auth layer. CVE-2025-29927 showed that sending `x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware` completely bypasses this check. Every route handler assumes auth was already done.

---

## 3. Vulnerable Code Examples

### Example 1: Server Action Without Auth Check

```tsx
// app/actions.ts
'use server';

import { db } from '@/lib/db';
import { revalidatePath } from 'next/cache';

// 💀 VULNERABLE: No authentication or authorization
export async function updateUserRole(userId: string, role: string) {
  await db.user.update({
    where: { id: userId },
    data: { role },
  });
  revalidatePath('/admin/users');
}

// 💀 VULNERABLE: No ownership check
export async function deletePost(postId: string) {
  // Anyone can delete any post — no session check, no ownership verification
  await db.post.delete({ where: { id: postId } });
  revalidatePath('/posts');
}
```

### Example 2: 'use client' on Sensitive Data Component

```tsx
'use client';

// 💀 VULNERABLE: This component exposes DB credentials and queries to client
import { createClient } from '@supabase/supabase-js';

// These are server-side-only secrets!
const supabase = createClient(
  process.env.SUPABASE_URL!,        // In client bundle!
  process.env.SUPABASE_SERVICE_KEY! // In client bundle — full DB access!
);

export function AdminQuery() {
  // ... runs queries directly from browser
}
```

### Example 3: Direct DB Query in RSC Without Validation

```tsx
// app/users/[id]/page.tsx
import { db } from '@/lib/db';

// 💀 VULNERABLE: No auth, no validation
export default async function UserProfile({ params }: { params: { id: string } }) {
  // No session check — anyone can view any user's profile
  // No input validation — SQL injection if using raw queries
  const user = await db.user.findUnique({
    where: { id: params.id },
  });
  
  return <div>{user.email} — {user.ssn}</div>; // Exposes PII!
}
```

### Example 4: File Upload to Public Directory

```tsx
'use server';

import { writeFile, mkdir } from 'fs/promises';
import path from 'path';

// 💀 VULNERABLE: Upload to public directory with no validation
export async function uploadAvatar(formData: FormData) {
  const file = formData.get('avatar') as File;
  
  // No file type validation!
  // No size limit!
  // No filename sanitization!
  const bytes = await file.arrayBuffer();
  const buffer = Buffer.from(bytes);
  
  const uploadDir = path.join(process.cwd(), 'public', 'avatars');
  await mkdir(uploadDir, { recursive: true });
  
  // Path traversal possible with "../../etc/passwd"
  await writeFile(path.join(uploadDir, file.name), buffer);
  
  return { url: `/avatars/${file.name}` };
}
```

### Example 5: Unvalidated Redirect After Auth

```tsx
// 💀 VULNERABLE: Open redirect
export async function GET(req: NextRequest) {
  const { searchParams } = new URL(req.url);
  const redirectTo = searchParams.get('redirect'); // e.g., "https://evil.com"
  
  // No validation!
  return NextResponse.redirect(new URL(redirectTo, req.url));
}
```

### Example 6: Server Action Mass Assignment

```tsx
'use server';

// 💀 VULNERABLE: Mass assignment — accepts any field from client
export async function updateProfile(userId: string, formData: FormData) {
  const data = Object.fromEntries(formData); // { name, email, role, isAdmin, ... }
  
  // Attacker sends { role: "admin", isAdmin: "true" }
  await db.user.update({
    where: { id: userId },
    data, // ← All fields from client applied directly!
  });
}
```

---

## 4. Secure Code Fix

### Fix 1: Auth Check in Every Server Action

```tsx
// app/actions.ts
'use server';

import { auth } from '@/lib/auth'; // Your auth library
import { db } from '@/lib/db';
import { revalidatePath } from 'next/cache';
import { z } from 'zod';

export async function updateUserRole(userId: string, role: string) {
  // ✅ 1. Authenticate
  const session = await auth();
  if (!session?.user) {
    throw new Error('Unauthorized');
  }
  
  // ✅ 2. Authorize
  if (session.user.role !== 'admin') {
    throw new Error('Forbidden');
  }
  
  // ✅ 3. Validate input
  const validRoles = ['user', 'moderator', 'admin'];
  if (!validRoles.includes(role)) {
    throw new Error('Invalid role');
  }
  
  await db.user.update({
    where: { id: userId },
    data: { role },
  });
  revalidatePath('/admin/users');
}

export async function deletePost(postId: string) {
  // ✅ Auth
  const session = await auth();
  if (!session?.user) throw new Error('Unauthorized');
  
  // ✅ Ownership check
  const post = await db.post.findUnique({ where: { id: postId } });
  if (!post) throw new Error('Not found');
  if (post.authorId !== session.user.id && session.user.role !== 'admin') {
    throw new Error('Forbidden');
  }
  
  await db.post.delete({ where: { id: postId } });
  revalidatePath('/posts');
}
```

### Fix 2: Route Group Protection with layout.ts

```tsx
// app/(admin)/layout.tsx — Protected admin layout
import { auth } from '@/lib/auth';
import { redirect } from 'next/navigation';

export default async function AdminLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  // ✅ Server-side auth check — runs for every page in the route group
  const session = await auth();
  
  if (!session?.user) {
    redirect('/login');
  }
  
  if (session.user.role !== 'admin') {
    redirect('/');
  }
  
  return (
    <div>
      <AdminSidebar user={session.user} />
      <main>{children}</main>
    </div>
  );
}
```

### Fix 3: Proper Middleware + Handler Defense-in-Depth

```tsx
// middleware.ts — First line of defense only
import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';

export function middleware(request: NextRequest) {
  // ✅ Strip dangerous internal headers at edge
  const requestHeaders = new Headers(request.headers);
  requestHeaders.delete('x-middleware-subrequest'); // CVE-2025-29927 mitigation
  
  const token = request.cookies.get('session');
  
  // Allow public routes
  if (request.nextUrl.pathname.startsWith('/api/auth/')) {
    return NextResponse.next();
  }
  
  // Protect admin routes
  if (request.nextUrl.pathname.startsWith('/admin')) {
    if (!token) {
      return NextResponse.redirect(new URL('/login', request.url));
    }
  }
  
  return NextResponse.next({
    request: { headers: requestHeaders },
  });
}
```

### Fix 4: File Upload with Validation and Safe Storage

```tsx
// lib/upload.ts
'use server';

import { writeFile } from 'fs/promises';
import path from 'path';
import { z } from 'zod';
import { auth } from '@/lib/auth';
import { v4 as uuid } from 'uuid';

const ALLOWED_TYPES = ['image/jpeg', 'image/png', 'image/webp', 'image/avif'];
const MAX_FILE_SIZE = 5 * 1024 * 1024; // 5MB

export async function uploadAvatar(formData: FormData) {
  // ✅ Auth
  const session = await auth();
  if (!session?.user) throw new Error('Unauthorized');
  
  const file = formData.get('avatar') as File;
  
  // ✅ Type validation
  if (!ALLOWED_TYPES.includes(file.type)) {
    throw new Error('Invalid file type');
  }
  
  // ✅ Size validation
  if (file.size > MAX_FILE_SIZE) {
    throw new Error('File too large');
  }
  
  // ✅ Sanitize filename — never trust user input
  const ext = file.type.split('/')[1]; // jpeg, png, webp
  const safeFilename = `${uuid()}.${ext}`;
  
  // ✅ Store outside public dir
  const uploadDir = path.join(process.cwd(), 'private', 'uploads');
  const bytes = await file.arrayBuffer();
  
  await writeFile(path.join(uploadDir, safeFilename), Buffer.from(bytes));
  
  // Serve through a controlled API endpoint with auth
  return { fileId: safeFilename };
}
```

### Fix 5: Input Validation with Zod (Mass Assignment Prevention)

```tsx
'use server';

import { z } from 'zod';
import { auth } from '@/lib/auth';
import { db } from '@/lib/db';

// ✅ Define exact schema — only these fields are accepted
const UpdateProfileSchema = z.object({
  name: z.string().min(1).max(100),
  bio: z.string().max(500).optional(),
  avatarUrl: z.string().url().optional(),
  // ⛔ role and isAdmin are NOT in the schema
});

export async function updateProfile(formData: FormData) {
  const session = await auth();
  if (!session?.user) throw new Error('Unauthorized');
  
  const raw = Object.fromEntries(formData);
  
  // ✅ Parse and validate — extra fields are stripped
  const parsed = UpdateProfileSchema.safeParse(raw);
  if (!parsed.success) {
    throw new Error(`Validation failed: ${parsed.error.message}`);
  }
  
  // ✅ Only validated fields reach the database
  await db.user.update({
    where: { id: session.user.id },
    data: parsed.data,
  });
  
  revalidatePath('/profile');
}
```

---

## 5. React/Next.js Specific Vulnerabilities (Verified CVEs)

### CVE-2025-55182 — React RSC RCE ("React2Shell")

| Field | Value |
|-------|-------|
| **Severity** | CRITICAL — CVSS 10.0 |
| **Type** | Pre-authentication Remote Code Execution |
| **CWE** | CWE-502 (Deserialization of Untrusted Data) |
| **Affected** | React 19.0.0–19.2.0; Next.js 14.x–15.x (RSC) |
| **Fixed in** | React 19.0.4+ / 19.1.5+ / 19.2.4+; Next.js 15.1.9+ / 15.2.6+ / 15.3.6+ / 15.4.8+ / 15.5.7+ |
| **Exploitation** | Actively exploited in the wild within 48 hours of disclosure |
| **Source** | https://nvd.nist.gov/vuln/detail/CVE-2025-55182 |

**Root Cause:** Unsafe deserialization in the React Server Components "Flight" protocol. Crafted HTTP requests to Server Function endpoints bypassed all authentication and achieved arbitrary code execution on the server.

**AI Connection:** AI-generated Next.js apps are especially vulnerable because they often use the default RSC setup without understanding the deserialization boundary. The `'use server'` directive automatically creates endpoints that AI does not secure.

### CVE-2025-29927 — Next.js Middleware Authorization Bypass

| Field | Value |
|-------|-------|
| **Severity** | CRITICAL — CVSS 9.1 |
| **Type** | Authorization Bypass |
| **CWE** | CWE-285 / CWE-863 (Improper/Incorrect Authorization) |
| **Affected** | Next.js 11.1.4–15.2.2 |
| **Fixed in** | 12.3.5, 13.5.9, 14.2.25, 15.2.3 |
| **Source** | https://nvd.nist.gov/vuln/detail/CVE-2025-29927 |

**Root Cause:** The internal `x-middleware-subrequest` header, used to prevent infinite middleware recursion, was client-controllable. Sending `x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware` caused Next.js to skip all middleware execution — including authentication checks, CSP headers, and geolocation guards.

**AI Connection:** AI-generated code commonly puts ALL authentication logic solely in middleware. This CVE demonstrates why middleware-only auth is catastrophic. AI rarely generates defense-in-depth with server-side auth in handlers.

### CVE-2025-57822 — Next.js SSRF via next()

| Field | Value |
|-------|-------|
| **Severity** | HIGH — CVSS 8.2 (NIST) / 6.5 (GitHub) |
| **Type** | Server-Side Request Forgery (SSRF) |
| **CWE** | CWE-918 (Server-Side Request Forgery) |
| **Affected** | Next.js < 14.2.32, < 15.4.7 |
| **Fixed in** | 14.2.32, 15.4.7 |
| **Source** | https://nvd.nist.gov/vuln/detail/CVE-2025-57822 |

**Root Cause:** When `next()` was called without explicitly passing the request object in self-hosted Next.js environments, user-supplied headers could be forwarded to internal services, enabling SSRF attacks.

**AI Connection:** AI generated middleware and route handlers often use `next()` without the request parameter, especially in custom middleware patterns for self-hosted deployments.

### CVE-2026-23864 — React RSC Denial of Service

| Field | Value |
|-------|-------|
| **Severity** | HIGH — CVSS 7.5 |
| **Type** | Denial of Service (DoS) |
| **CWE** | CWE-400 / CWE-502 / CWE-1284 |
| **Affected** | React 19.0.0–19.2.x |
| **Fixed in** | 19.0.4+, 19.1.5+, 19.2.4+ |
| **Source** | https://nvd.nist.gov/vuln/detail/CVE-2026-23864 |

**Root Cause:** Multiple uncontrolled resource consumption vectors in the React Server Components Flight protocol. Specially crafted HTTP requests to Server Function endpoints caused server crashes, OOM exceptions, or excessive CPU usage.

### CVE-2024-34351 — Next.js Server Actions SSRF

| Field | Value |
|-------|-------|
| **Severity** | HIGH — CVSS 7.5 |
| **Type** | Server-Side Request Forgery (SSRF) |
| **CWE** | CWE-918 (Server-Side Request Forgery) |
| **Affected** | Next.js 13.4.0–14.1.0 |
| **Fixed in** | 14.1.1 |
| **Source** | https://nvd.nist.gov/vuln/detail/CVE-2024-34351 |

**Root Cause:** Modifying the `Host` header allowed SSRF when Server Actions performed redirects to relative paths. An attacker could make requests appearing to originate from the Next.js server itself.

---

### CVE Cross-Reference Table

| CVE | CVSS | Type | Affected | Fixed | AI Risk |
|-----|------|------|----------|-------|---------|
| CVE-2025-55182 | 10.0 | RCE (RSC Flight) | React 19.0–19.2, Next 14–15 | React 19.0.4+, Next 15.1.9+ | Very High |
| CVE-2025-29927 | 9.1 | Auth Bypass | Next 11.1.4–15.2.2 | 12.3.5 / 13.5.9 / 14.2.25 / 15.2.3 | Very High |
| CVE-2025-57822 | 8.2 | SSRF | Next < 14.2.32, < 15.4.7 | 14.2.32 / 15.4.7 | Medium |
| CVE-2026-23864 | 7.5 | DoS | React 19.0–19.2 | 19.0.4+ / 19.1.5+ / 19.2.4+ | Medium |
| CVE-2024-34351 | 7.5 | SSRF (Server Actions) | Next 13.4.0–14.1.0 | 14.1.1 | High |

> **Note:** CVE-2025-66478 was **rejected** as a duplicate of CVE-2025-55182.

---

## 6. Prevention Checklist (15 Items)

- [ ] **Upgrade React to ≥ 19.0.4** (or 19.1.5+, 19.2.4+) to patch CVE-2025-55182 and CVE-2026-23864
- [ ] **Upgrade Next.js to ≥ 15.2.3** (or 14.2.25+) to patch CVE-2025-29927; ≥ 15.4.7 for CVE-2025-57822
- [ ] **Authenticate in every Server Action** — never rely solely on middleware for auth; verify `auth()` at the top of every `'use server'` function
- [ ] **Authorize by ownership** — in every mutation, verify `post.authorId === session.user.id` (or admin override)
- [ ] **Validate all input with Zod** — define exact schemas; never pass `Object.fromEntries(formData)` directly to a database
- [ ] **Use route group layouts for protected routes** — wrap `/admin` in `(admin)/layout.tsx` with server-side auth
- [ ] **Strip dangerous headers in middleware** — explicitly remove `x-middleware-subrequest` at the edge
- [ ] **Never upload files to `public/`** — store uploads outside the web root; serve through authenticated API endpoints
- [ ] **Validate file uploads strictly** — check MIME type, magic bytes, file size, and use UUID-based filenames
- [ ] **Avoid `'use client'` on data-fetching components** — keep data fetching in Server Components; only add `'use client'` for interactivity
- [ ] **Never expose secrets in client components** — `NEXT_PUBLIC_*` is visible to every visitor; use `process.env.SERVER_SECRET` only in Server Components/Actions
- [ ] **Block prototype pollution vectors** — guard `__proto__`, `constructor`, `prototype` in key-setting utilities; use `Object.create(null)` for FormData accumulators
- [ ] **Prevent open redirects** — validate redirect URLs against an allowlist; never accept user-controlled `redirect` params
- [ ] **Add CSP headers** — use middleware or `next.config.js` headers to add Content-Security-Policy: `script-src 'self'; object-src 'none'`
- [ ] **Run security scanning** — use `npm audit`, Snyk, or Semgrep rules (`vibe-javascript.yml`, `vibe-typescript.yml`) in CI

---

## 7. Vibe-Coding Red Flags (15 Items)

When reviewing AI-generated React/Next.js code, watch for these patterns:

1. ✅ **`'use client'` on every page** — indicates AI doesn't understand RSC boundaries; most pages should be Server Components
2. ✅ **Middleware as the only auth layer** — AI rarely adds auth inside route handlers or Server Actions
3. ✅ **`as Type` casts without runtime validation** — `const data = await res.json() as User` (no Zod parse)
4. ✅ **Server Actions that accept `formData` and pass it to DB directly** — `Object.fromEntries(formData)` is a mass-assignment red flag
5. ✅ **File uploads to `public/uploads/` or `public/avatars/`** — every AI framework boilerplate does this
6. ✅ **`dangerouslySetInnerHTML` without sanitization** — AI doesn't import DOMPurify or use `dangerouslySetInnerHTML={{ __html: userContent }}`
7. ✅ **No session/ownership check in delete endpoints** — `deletePost(postId)` without verifying `post.authorId`
8. ✅ **`NEXT_PUBLIC_*` with actual secrets** — AI doesn't distinguish public from private env vars
9. ✅ **Open redirect patterns** — `searchParams.get('redirect')` used without validation in redirect logic
10. ✅ **No rate limiting on auth endpoints** — AI generates login/register forms without rate limit checks
11. ✅ **`<Link>` without `rel="noopener noreferrer"`** for external URLs
12. ✅ **Exposing internal API structure** — `/api/users/${userId}` patterns that let attackers enumerate user IDs
13. ✅ **`eval()` or `new Function()` in any form** — AI uses these for dynamic template rendering
14. ✅ **No error boundaries** — unhandled promise rejections in Server Components can leak stack traces
15. ✅ **Old Next.js versions in `package.json`** — AI often pins `"next": "14.0.0"` or `"next": "13.5.0"` without knowing about CVEs

---

## Key Takeaways

1. **Framework isolation is not security isolation** — the RSC boundary, middleware, and `'use client'` directive are optimization features, not security guarantees
2. **Every server endpoint needs independent auth** — Server Actions, Route Handlers, and pages must each verify authentication and authorization
3. **AI amplifies framework-level CVEs** — generated code uses default patterns that are most impacted by framework bugs (middleware-only auth, RSC deserialization)
4. **Defense in depth is non-negotiable** — middleware + layout auth + handler auth + input validation + output encoding
5. **Keep React and Next.js patched** — multiple critical CVEs in 2025-2026 demonstrate active exploitation of framework bugs
6. **Runtime validation beats type safety** — TypeScript types erase at runtime; Zod (or equivalent) is mandatory for all I/O boundaries

---

## References

- https://nvd.nist.gov/vuln/detail/CVE-2025-55182
- https://nvd.nist.gov/vuln/detail/CVE-2025-29927
- https://nvd.nist.gov/vuln/detail/CVE-2025-57822
- https://nvd.nist.gov/vuln/detail/CVE-2026-23864
- https://nvd.nist.gov/vuln/detail/CVE-2024-34351
- https://react.dev/blog/2025/12/03/critical-security-vulnerability-in-react-server-components
- https://github.com/vercel/next.js/security/advisories/GHSA-f82v-jwr5-mffw
- https://github.com/vercel/next.js/security/advisories/GHSA-4342-x723-ch2f
- https://www.facebook.com/security/advisories/cve-2026-23864
