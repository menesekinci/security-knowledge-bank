---
source: "languages/go/race-conditions.md"
title: "Race Conditions — Data Races, Sync Misuse, and Race Detector Limits"
heading: "Real CVEs"
category: "language-vuln"
language: "go"
severity: "medium"
tags: [ai-generated, does, go, language-vuln, vulnerability]
chunk: 11/12
---

## Real CVEs

- **CVE-2025-47907 (database/sql, CVSS 7.0)**: A genuine **data race** (CWE-362) in the standard library. If a query's context is cancelled during a `Rows.Scan()` call while other queries run in parallel, the results can be overwritten with those of another query — so `Scan` returns another query's data or an error. A confidentiality/integrity issue, not just a crash. Fixed in Go 1.23.12 and 1.24.6.
- **CVE-2021-36221 (net/http/httputil, CVSS 5.9)**: A **race condition** in `ReverseProxy` could trigger a panic when a request is aborted with `ErrAbortHandler` while another request is being processed concurrently — an availability (DoS) impact on proxy servers. Fixed in Go 1.15.15 and 1.16.7.