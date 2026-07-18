---
source: "languages/python/command-injection.md"
title: "Command Injection — Python"
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
| **CVE-2020-16846** | SaltStack Salt ≤3002 — unauthenticated shell injection in the salt-api SSH client (params like `ssh_options` passed to a shell string) | Unauthenticated RCE |
| **CVE-2022-24439** | GitPython <3.1.30 — argument injection via a crafted `ext::sh -c ...` clone URL passed to `git` | RCE |
| **CVE-2022-24065** | cookiecutter <2.1.1 — command injection via the `checkout` parameter (Mercurial `hg` argument injection) | RCE |
| **CVE-2020-11981** | Apache Airflow ≤1.10.10 — CeleryExecutor runs unsanitized commands taken from the message broker | Worker RCE |
| **CVE-2024-45595** | D-Tale <3.14.1 — arbitrary OS command execution via the Chart Builder "Custom Filter" input | RCE |

---