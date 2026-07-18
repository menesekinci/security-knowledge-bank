---
source: "languages/javascript/react-security.md"
title: "React & Next.js Security Deep Dive"
heading: "2. dangerouslySetInnerHTML"
category: "language-vuln"
language: "javascript"
severity: "critical"
tags: [cve-2025-55182, cve-2025-66478, dangerouslysetinnerhtml, injection, javascript, language-vuln, overview, risks]
chunk: 4/15
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