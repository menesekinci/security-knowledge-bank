---
source: "languages/python/sql-injection.md"
title: "SQL Injection — Python"
heading: "Real-World CVEs"
category: "language-vuln"
language: "python"
severity: "critical"
tags: [checklist, code, explanation, language-vuln, prevention, python, secure, vulnerability, vulnerable]
chunk: 7/8
---

## Real-World CVEs

| CVE | Description | Impact |
|---|---|---|
| **CVE-2022-28346** | Django — SQLi in `QuerySet.annotate()`/`aggregate()`/`extra()` via crafted column-alias `**kwargs` | Arbitrary SQL execution |
| **CVE-2022-34265** | Django — SQLi via untrusted `Trunc(kind)` / `Extract(lookup_name)` arguments | Arbitrary SQL execution |
| **CVE-2021-35042** | Django — SQLi via unsanitized `QuerySet.order_by()` input | Arbitrary SQL execution |
| **CVE-2020-7471** | Django — SQLi via a crafted `StringAgg(delimiter)` in `contrib.postgres` | Arbitrary SQL execution |
| **CVE-2024-53908** | Django — SQLi in the `HasKey(lhs, rhs)` JSON lookup on Oracle | Arbitrary SQL execution |

---