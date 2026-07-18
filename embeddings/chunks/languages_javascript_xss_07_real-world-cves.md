---
source: "languages/javascript/xss.md"
title: "Cross-Site Scripting (XSS) — DOM-Based"
heading: "Real-World CVEs"
category: "language-vuln"
language: "javascript"
severity: "critical"
tags: [checklist, code, explanation, javascript, language-vuln, prevention, secure, vulnerability, vulnerable]
chunk: 7/8
---

## Real-World CVEs

| CVE | Description | Impact |
|---|---|---|
| **CVE-2025-23786** | CISA-reported DOM XSS via innerHTML (multiple vendors) | Cross-site scripting |
| **CVE-2024-29650** | Prototype pollution leading to DOM XSS | Chained XSS |
| **CVE-2024-23832** | DOM XSS in markdown-it via unescaped HTML | Rich text XSS |
| **CVE-2023-44487** | HTTP/2 rapid reset + XSS chain | Combined DoS + XSS |
| **CVE-2023-22527** | Atlassian Confluence XSS (via template injection) | Remote code execution |

---