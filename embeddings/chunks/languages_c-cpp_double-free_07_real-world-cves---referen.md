---
source: "languages/c-cpp/double-free.md"
title: "Double-Free Memory Corruption (C/C++)"
heading: "Real-World CVEs / References"
category: "language-vuln"
language: "c-cpp"
severity: "critical"
tags: [c-cpp, checklist, code, explanation, language-vuln, prevention, secure, vulnerability, vulnerable]
chunk: 7/8
---

## Real-World CVEs / References

| CVE | Notes |
|-----|--------|
| [CVE-2021-3156](https://nvd.nist.gov/vuln/detail/CVE-2021-3156) | sudo heap-based buffer overflow (Baron Samedit) — illustrates critical impact of heap corruption classes adjacent to free-list abuse |
| [CVE-2015-0235](https://nvd.nist.gov/vuln/detail/CVE-2015-0235) | GHOST — glibc heap/buffer issues in name resolution path; ecosystem-wide native code risk |
| [CVE-2014-0160](https://nvd.nist.gov/vuln/detail/CVE-2014-0160) | Heartbleed — memory disclosure from native TLS stack; underscores why heap hygiene and bounds matter in C libraries |
| [CWE-415](https://cwe.mitre.org/data/definitions/415.html) | Double Free |
| [CWE-416](https://cwe.mitre.org/data/definitions/416.html) | Use After Free (often co-located bugs) |
| [OWASP Code Review — Memory](https://owasp.org/www-project-code-review-guide/) | Review patterns for alloc/free |

Many product CVEs are filed as “heap corruption” or “use-after-free” where double-free is the root trigger; always map allocator reports carefully.

---