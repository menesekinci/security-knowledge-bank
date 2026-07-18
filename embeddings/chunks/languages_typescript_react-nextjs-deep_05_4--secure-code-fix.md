---
source: "languages/typescript/react-nextjs-deep.md"
title: "React/Next.js Deep Security — AI-Generated Code Edition"
heading: "4. Secure Code Fix"
category: "language-vuln"
language: "typescript"
severity: "critical"
tags: [code, explanation, language-vuln, next, react, secure, typescript, vulnerability, vulnerable]
chunk: 5/10
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