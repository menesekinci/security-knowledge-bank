---
source: "languages/javascript/react-security.md"
title: "React & Next.js Security Deep Dive"
heading: "9. Content Security Policy"
category: "language-vuln"
language: "javascript"
severity: "critical"
tags: [cve-2025-55182, cve-2025-66478, dangerouslysetinnerhtml, injection, javascript, language-vuln, overview, risks]
chunk: 11/15
---

## 9. Content Security Policy

**Secure Code:**
```typescript
// next.config.js — ✅ CSP headers
const cspHeader = `
  default-src 'self';
  script-src 'self' 'unsafe-eval' 'unsafe-inline';
  style-src 'self' 'unsafe-inline';
  img-src 'self' blob: data:;
  font-src 'self';
  object-src 'none';
  base-uri 'self';
  form-action 'self';
  frame-ancestors 'none';
  block-all-mixed-content;
  upgrade-insecure-requests;
`;

module.exports = {
  async headers() {
    return [
      {
        source: "/(.*)",
        headers: [
          {
            key: "Content-Security-Policy",
            value: cspHeader.replace(/\s{2,}/g, " ").trim(),
          },
        ],
      },
    ];
  },
};
```

---