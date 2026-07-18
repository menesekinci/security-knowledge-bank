---
source: "languages/javascript/eval-injection.md"
title: "Eval Injection — JavaScript"
category: "language-vuln"
language: "javascript"
chunk: 7
total_chunks: 8
heading: "Real-World CVEs"
---

## Real-World CVEs

| CVE | Description | Impact |
|---|---|---|
| **CVE-2024-6982** | Lollms eval injection (Python, but pattern applies to JS) | RCE in AI chat platform |
| **CVE-2023-25166** | Apache Airflow eval injection via template rendering | RCE in workflow system |
| **CVE-2022-25829** | Node.js vm module escape via constructor chain | Sandbox escape |
| **CVE-2021-23426** | Vm2 sandbox escape via Proxy | Sandbox escape |
| **CVE-2020-7753** | `function` constructor injection in template engines | RCE |

---