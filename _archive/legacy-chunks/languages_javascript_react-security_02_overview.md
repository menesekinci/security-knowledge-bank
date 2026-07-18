---
source: "languages/javascript/react-security.md"
title: "React & Next.js Security Deep Dive"
category: "language-vuln"
language: "javascript"
chunk: 2
total_chunks: 15
heading: "Overview"
---

## Overview

React provides built-in XSS protections through JSX escaping, but several attack surfaces remain. With the rise of React Server Components (RSC) and Next.js App Router, new vulnerability classes have emerged including critical RCE via the Flight protocol (CVE-2025-55182) and middleware authorization bypass (CVE-2025-29927).

---