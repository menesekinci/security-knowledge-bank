---
source: "languages/javascript/react-security.md"
title: "React & Next.js Security Deep Dive"
heading: "6. Next.js Route Handler Security"
category: "language-vuln"
language: "javascript"
severity: "critical"
tags: [cve-2025-55182, cve-2025-66478, dangerouslysetinnerhtml, injection, javascript, language-vuln, overview, risks]
chunk: 8/15
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