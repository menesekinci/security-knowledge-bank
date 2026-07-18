---
source: "languages/javascript/react-security.md"
title: "React & Next.js Security Deep Dive"
heading: "8. Next.js API / Data Exposure"
category: "language-vuln"
language: "javascript"
severity: "critical"
tags: [cve-2025-55182, cve-2025-66478, dangerouslysetinnerhtml, injection, javascript, language-vuln, overview, risks]
chunk: 10/15
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