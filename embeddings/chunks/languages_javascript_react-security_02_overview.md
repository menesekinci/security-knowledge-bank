---
source: "languages/javascript/react-security.md"
title: "React & Next.js Security Deep Dive"
heading: "Overview"
category: "language-vuln"
language: "javascript"
severity: "critical"
tags: [cve-2025-55182, cve-2025-66478, dangerouslysetinnerhtml, injection, javascript, language-vuln, overview, risks]
chunk: 2/15
---

## Overview

React provides built-in XSS protections through JSX escaping, but several attack surfaces remain. With the rise of React Server Components (RSC) and Next.js App Router, new vulnerability classes have emerged including critical RCE via the Flight protocol (CVE-2025-55182) and middleware authorization bypass (CVE-2025-29927).

---