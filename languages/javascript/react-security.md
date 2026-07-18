# React & Next.js Security Deep Dive

> **Category:** JavaScript / React Security Knowledge Bank  
> **Focus:** dangerouslySetInnerHTML, JSX injection, SSR risks, Next.js server actions, route handler security  
> **Last Updated:** July 2026

---

## Overview

React provides built-in XSS protections through JSX escaping, but several attack surfaces remain. With the rise of React Server Components (RSC) and Next.js App Router, new vulnerability classes have emerged including critical RCE via the Flight protocol (CVE-2025-55182) and middleware authorization bypass (CVE-2025-29927).

---

## 1. CVE-2025-55182 / CVE-2025-66478 — React Server Components RCE (React2Shell)

**CVSS:** 10.0 (Critical)  
**Affected:** React 19.0.0, 19.1.0, 19.1.1, 19.2.0 (fixed in 19.2.1+)  
**Affected (Next.js):** Versions using React 19 RSC protocol  
**Description:** Unauthenticated remote code execution vulnerability in the Flight protocol used by React Server Components. An attacker can send a crafted HTTP request to deserialize arbitrary data, leading to RCE. CVE-2025-66478 was originally filed for Next.js but was later determined to be a duplicate of CVE-2025-55182.

**Vulnerable Code:**
```javascript
// 💀 VULNERABLE — Using React 19 < 19.2.1 with RSC
// Any page or component using React Server Components is vulnerable
// No specific code change — it's a protocol-level vulnerability

// next.config.js — 💀 No mitigation possible without patching
```

**Secure Code:**
```javascript
// ✅ SECURE — Upgrade React to patched version
// React 19.2.1+ / Next.js 14.2.28+ / 15.2.5+
// Also consider disabling RSC if not needed:
module.exports = {
  experimental: {
    serverComponents: false,  // Disable RSC if not needed (Next.js 13/14)
  },
};
```

**Source:**
- https://react.dev/blog/2025/12/03/critical-security-vulnerability-in-react-server-components
- https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/
- https://nvd.nist.gov/vuln/detail/CVE-2025-55182

---

## 2. dangerouslySetInnerHTML

### Vulnerability

**Vulnerable Code:**
```jsx
// 💀 VULNERABLE — Directly injecting unsanitized user content
function CommentView({ comment }) {
  return (
    <div dangerouslySetInnerHTML={{ __html: comment.body }} />
  );
  // 💀 comment.body from user = <img src=x onerror=alert('XSS')>
}
```

**Secure Code:**
```jsx
// ✅ SECURE — Sanitize before using dangerouslySetInnerHTML
import DOMPurify from "dompurify";

function CommentView({ comment }) {
  const sanitized = DOMPurify.sanitize(comment.body, {
    ALLOWED_TAGS: ["b", "i", "em", "strong", "a"],
    ALLOWED_ATTR: ["href"],
  });
  return <div dangerouslySetInnerHTML={{ __html: sanitized }} />;
}
```

### Common AI Misconfiguration

```jsx
// 💀 VULNERABLE — AI often misses sanitization
function RichTextRenderer({ html }) {
  // AI-generated code frequently uses dangerouslySetInnerHTML without DOMPurify
  return <div dangerouslySetInnerHTML={{ __html: html }} />;
}
```

---

## 3. JSX Injection

### React's Default Protection

React automatically escapes values embedded in JSX. However, there are edge cases:

**Vulnerable Code:**
```jsx
// 💀 VULNERABLE — Using user-provided component names or URLs
function UserProfile({ user }) {
  const UserIcon = user.iconComponent;  // 💀 User controls which component renders
  return <UserIcon />;
}
```

```jsx
// 💀 VULNERABLE — href with javascript: protocol
function UserLink({ user }) {
  return <a href={user.website}>{user.name}</a>;
  // 💀 user.website = "javascript:alert('XSS')"
}
```

**Secure Code:**
```jsx
// ✅ SECURE — Validate URLs
function UserLink({ user }) {
  const url = new URL(user.website);
  if (url.protocol !== "https:" && url.protocol !== "http:") {
    return <span>{user.name}</span>;  // Block non-HTTP protocols
  }
  return <a href={url.href}>{user.name}</a>;
}
```

---

## 4. SSR Risks — Server-Side Data Leakage

**Vulnerable Code:**
```jsx
// 💀 VULNERABLE — Server-side rendering leaking sensitive data
// pages/profile.js (Next.js Pages Router)
export async function getServerSideProps({ req }) {
  const user = await getUser(req.cookies.token);
  
  return {
    props: {
      user: {
        ...user,
        passwordHash: user.password_hash,  // 💀 Sent to client!
        ssnLast4: user.ssn_last_4,         // 💀 PII in SSR props
      },
    },
  };
}
```

**Secure Code:**
```jsx
// ✅ SECURE — Strip sensitive data before SSR
export async function getServerSideProps({ req }) {
  const user = await getUser(req.cookies.token);
  
  const safeUser = {
    id: user.id,
    username: user.username,
    email: user.email,
    avatarUrl: user.avatar_url,
    // ✅ password_hash, ssn intentionally excluded
  };
  
  return {
    props: { user: safeUser },
  };
}
```

---

## 5. Next.js Server Actions Security

### Missing Authorization in Server Actions

**Vulnerable Code:**
```typescript
// app/actions.ts — 💀 No authentication check
"use server";

export async function deleteUser(userId: string) {
  // 💀 No authorization — anyone who knows the action can call it
  await db.user.delete({ where: { id: userId } });
  revalidatePath("/users");
}
```

**Secure Code:**
```typescript
// app/actions.ts — ✅ Server-side authorization
"use server";
import { auth } from "@/lib/auth";
import { revalidatePath } from "next/cache";

export async function deleteUser(userId: string) {
  const session = await auth();
  
  if (!session?.user) {
    throw new Error("Unauthenticated");
  }
  
  // Verify the user can only delete their own account (or is admin)
  if (session.user.id !== userId && session.user.role !== "admin") {
    throw new Error("Unauthorized");
  }
  
  await db.user.delete({ where: { id: userId } });
  revalidatePath("/users");
}
```

### Input Validation in Server Actions

**Vulnerable Code:**
```typescript
// 💀 VULNERABLE — No input validation in server actions
"use server";

export async function createPost(formData: FormData) {
  const title = formData.get("title") as string;   // 💀 No validation
  const content = formData.get("content") as string; // 💀 No sanitization
  
  await db.post.create({
    data: { title, content },
  });
  revalidatePath("/posts");
}
```

**Secure Code:**
```typescript
// ✅ SECURE — Validate with Zod or similar
"use server";
import { z } from "zod";
import { revalidatePath } from "next/cache";

const PostSchema = z.object({
  title: z.string().min(1).max(200),
  content: z.string().min(1).max(10000),
});

export async function createPost(formData: FormData) {
  const raw = {
    title: formData.get("title"),
    content: formData.get("content"),
  };
  
  const parsed = PostSchema.safeParse(raw);
  if (!parsed.success) {
    return { error: parsed.error.flatten() };
  }
  
  await db.post.create({
    data: { 
      title: parsed.data.title, 
      content: sanitizeHtml(parsed.data.content),
    },
  });
  revalidatePath("/posts");
}
```

---

## 6. Next.js Route Handler Security

### CWE-285: Missing Authorization in Route Handlers

**Vulnerable Code:**
```typescript
// app/api/users/[id]/route.ts — 💀 No authorization
import { NextResponse } from "next/server";

export async function GET(
  request: Request,
  { params }: { params: { id: string } }
) {
  const user = await db.user.findUnique({
    where: { id: params.id },
  });
  return NextResponse.json(user);  // 💀 Any user data returned to anyone
}
```

**Secure Code:**
```typescript
// app/api/users/[id]/route.ts — ✅ Authorization + validation
import { NextResponse } from "next/server";
import { auth } from "@/lib/auth";

export async function GET(
  request: Request,
  { params }: { params: { id: string } }
) {
  const session = await auth();
  if (!session?.user) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }
  
  // Users can only view their own profile unless admin
  if (session.user.id !== params.id && session.user.role !== "admin") {
    return NextResponse.json({ error: "Forbidden" }, { status: 403 });
  }
  
  const user = await db.user.findUnique({
    where: { id: params.id },
    select: { id: true, username: true, email: true }, // ✅ Only safe fields
  });
  
  if (!user) {
    return NextResponse.json({ error: "Not found" }, { status: 404 });
  }
  
  return NextResponse.json(user);
}
```

---

## 7. CVE-2025-29927 — Next.js Middleware Authorization Bypass

**CVSS:** 9.1 (Critical)  
**Affected:** Next.js 12.0.0 — 15.2.2 (fixed in 15.2.3, 14.2.25, 13.5.9, 12.3.5)  
**Description:** It is possible to bypass authorization checks within a Next.js application if the authorization check occurs in middleware. An attacker sends the `x-middleware-subrequest` header to bypass middleware-based auth.

**Vulnerable Pattern:**
```typescript
// middleware.ts — 💀 Middleware that can be bypassed
import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";

export function middleware(request: NextRequest) {
  const token = request.cookies.get("session_token");
  
  if (!token) {
    return NextResponse.redirect(new URL("/login", request.url));
  }
  // 💀 This middleware can be completely bypassed via x-middleware-subrequest header
}
```

**Secure Code:**
```typescript
// ✅ SECURE — Upgrade to patched Next.js version
// AND move critical auth checks to Route Handlers or Server Actions
// AND verify auth inside each protected route handler

// middleware.ts — Defense in depth with additional cookie verification
export function middleware(request: NextRequest) {
  // Block direct access attempts
  const bypassHeader = request.headers.get("x-middleware-subrequest");
  if (bypassHeader) {
    return NextResponse.json({ error: "Forbidden" }, { status: 403 });
  }
  
  const token = request.cookies.get("session_token");
  if (!token) {
    return NextResponse.redirect(new URL("/login", request.url));
  }
}
```

**Source:** https://nvd.nist.gov/vuln/detail/CVE-2025-29927

---

## 8. Next.js API / Data Exposure

### Server-Side Data Exposure via Client Components

**Vulnerable Code:**
```jsx
// 💀 VULNERABLE — Client component fetching with API key
"use client";

async function fetchData() {
  const res = await fetch("https://api.example.com/data", {
    headers: {
      "API-Key": process.env.NEXT_PUBLIC_API_KEY,  // 💀 NEXT_PUBLIC_ exposed to client!
    },
  });
  return res.json();
}
```

**Secure Code:**
```jsx
// ✅ SECURE — Keep secrets server-side, use API routes
// app/api/data/route.ts (server-only)
export async function GET() {
  const res = await fetch("https://api.example.com/data", {
    headers: {
      "API-Key": process.env.API_KEY,  // ✅ Not prefixed with NEXT_PUBLIC_
    },
  });
  return new Response(res.body);
}

// Client component calls our API route instead
"use client";

async function fetchData() {
  const res = await fetch("/api/data");  // ✅ Through server API route
  return res.json();
}
```

---

## 9. Content Security Policy

**Secure Code:**
```typescript
// next.config.js — ✅ CSP headers
const cspHeader = `
  default-src 'self';
  script-src 'self' 'unsafe-eval' 'unsafe-inline';
  style-src 'self' 'unsafe-inline';
  img-src 'self' blob: data:;
  font-src 'self';
  object-src 'none';
  base-uri 'self';
  form-action 'self';
  frame-ancestors 'none';
  block-all-mixed-content;
  upgrade-insecure-requests;
`;

module.exports = {
  async headers() {
    return [
      {
        source: "/(.*)",
        headers: [
          {
            key: "Content-Security-Policy",
            value: cspHeader.replace(/\s{2,}/g, " ").trim(),
          },
        ],
      },
    ];
  },
};
```

---

## 10. CVE Roundup

| CVE | CVSS | Affected | Type | Fixed In |
|-----|------|----------|------|----------|
| CVE-2025-55182 | 10.0 | React 19.0 – 19.2.0 | RCE (Flight Protocol) | React 19.2.1+ |
| CVE-2025-66478 | 10.0 | Next.js with RSC | RCE (duplicate) | See CVE-2025-55182 fix |
| CVE-2025-29927 | 9.1 | Next.js 12–15.2.2 | Middleware Bypass | 15.2.3, 14.2.25 |
| CVE-2024-51479 | 7.5 | Next.js <= 14.2.15 | Authorization Bypass | 14.2.16+ |

---

## 11. Version Recommendations

| Framework | Version | Status | Notes |
|-----------|---------|--------|-------|
| React | 19.2.1+ | ✅ Latest | Patch CVE-2025-55182 |
| Next.js | 15.2.3+ | ✅ Latest | Patch CVE-2025-29927 |
| Next.js (LTS) | 14.2.25+ | ✅ LTS | If on 14.x |

---

## 12. Common AI-Produced Misconfigurations

1. **`dangerouslySetInnerHTML` without DOMPurify** — Forgetting to sanitize HTML
2. **Missing auth in Server Actions** — No session check before mutations
3. **NEXT_PUBLIC_ prefix on secrets** — Client-side exposure of API keys
4. **Missing authorization in Route Handlers** — API routes without auth
5. **User-controlled component rendering** — `user.component` as JSX component
6. **`javascript:` URLs in href** — Not validating URL protocols
7. **SSR leaking sensitive data** — Password hashes in server component props
8. **Insecure cookies** — Missing `httpOnly`, `secure`, `sameSite` flags
9. **No input validation in Server Actions** — Direct FormData to database
10. **Disabling CSP** — Setting `Content-Security-Policy` too permissive

---

## Verification / Source URLs

- React Security Advisory (CVE-2025-55182): https://react.dev/blog/2025/12/03/critical-security-vulnerability-in-react-server-components
- Next.js CVE-2025-66478: https://nextjs.org/blog/CVE-2025-66478
- Next.js CVE-2025-29927: https://nvd.nist.gov/vuln/detail/CVE-2025-29927
- Unit42 Analysis: https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/
- React Security Best Practices: https://corgea.com/learn/react-security-best-practices-2025
- Next.js Server Action Security: https://blog.arcjet.com/next-js-server-action-security/
- OWASP XSS Prevention: https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html
