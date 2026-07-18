---
source: "languages/typescript/react-nextjs-deep.md"
title: "React/Next.js Deep Security — AI-Generated Code Edition"
heading: "3. Vulnerable Code Examples"
category: "language-vuln"
language: "typescript"
severity: "critical"
tags: [code, explanation, language-vuln, next, react, secure, typescript, vulnerability, vulnerable]
chunk: 4/10
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