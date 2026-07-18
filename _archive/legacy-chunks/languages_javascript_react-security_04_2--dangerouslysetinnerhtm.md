---
source: "languages/javascript/react-security.md"
title: "React & Next.js Security Deep Dive"
category: "language-vuln"
language: "javascript"
chunk: 4
total_chunks: 15
heading: "2. dangerouslySetInnerHTML"
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