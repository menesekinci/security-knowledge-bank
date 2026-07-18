---
source: "languages/javascript/react-security.md"
title: "React & Next.js Security Deep Dive"
heading: "4. SSR Risks — Server-Side Data Leakage"
category: "language-vuln"
language: "javascript"
severity: "critical"
tags: [cve-2025-55182, cve-2025-66478, dangerouslysetinnerhtml, injection, javascript, language-vuln, overview, risks]
chunk: 6/15
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