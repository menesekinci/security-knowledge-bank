---
source: "languages/typescript/react-nextjs-deep.md"
title: "React/Next.js Deep Security — AI-Generated Code Edition"
heading: "2. How AI / Vibe Coding Generates These Vulnerabilities"
category: "language-vuln"
language: "typescript"
severity: "critical"
tags: [code, explanation, language-vuln, next, react, secure, typescript, vulnerability, vulnerable]
chunk: 3/10
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