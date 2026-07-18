---
source: "languages/javascript/react-security.md"
title: "React & Next.js Security Deep Dive"
category: "language-vuln"
language: "javascript"
chunk: 6
total_chunks: 15
heading: "4. SSR Risks — Server-Side Data Leakage"
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