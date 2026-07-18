---
source: "languages/javascript/react-security.md"
title: "React & Next.js Security Deep Dive"
heading: "3. JSX Injection"
category: "language-vuln"
language: "javascript"
severity: "critical"
tags: [cve-2025-55182, cve-2025-66478, dangerouslysetinnerhtml, injection, javascript, language-vuln, overview, risks]
chunk: 5/15
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