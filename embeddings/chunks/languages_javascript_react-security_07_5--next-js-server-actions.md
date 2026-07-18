---
source: "languages/javascript/react-security.md"
title: "React & Next.js Security Deep Dive"
heading: "5. Next.js Server Actions Security"
category: "language-vuln"
language: "javascript"
severity: "critical"
tags: [cve-2025-55182, cve-2025-66478, dangerouslysetinnerhtml, injection, javascript, language-vuln, overview, risks]
chunk: 7/15
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