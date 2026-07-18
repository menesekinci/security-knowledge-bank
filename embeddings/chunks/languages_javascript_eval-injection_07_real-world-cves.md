---
source: "languages/javascript/eval-injection.md"
title: "Eval Injection — JavaScript"
heading: "Real-World CVEs"
category: "language-vuln"
language: "javascript"
severity: "critical"
tags: [checklist, code, explanation, javascript, language-vuln, prevention, secure, vulnerability, vulnerable]
chunk: 7/8
---

## Real-World CVEs

All of the following are real, NVD-verified JavaScript/Node.js code-execution CVEs in `vm2` — the exact sandbox library this page recommends treating with caution. They demonstrate why `vm`/`vm2` are not a security boundary: attacker-supplied code passed to the sandbox escapes to the host and runs arbitrary commands.

| CVE | Description | Impact |
|---|---|---|
| **CVE-2023-29017** | `vm2` <= 3.9.14 — host objects passed to `Error.prepareStackTrace` on unhandled async errors let sandboxed code reach the host | Sandbox escape → RCE (CVSS 9.8; fixed 3.9.15) |
| **CVE-2023-37466** | `vm2` <= 3.9.19 — Promise handler sanitization bypassed via the `@@species` accessor property | Sandbox escape → RCE (CVSS 10.0; fixed 3.10.0) |
| **CVE-2023-32314** | `vm2` <= 3.9.17 — unexpected creation of a host object via `Proxy` | Sandbox escape → RCE (CVSS 10.0; fixed 3.9.18) |
| **CVE-2022-36067** | `vm2` < 3.9.11 ("Sandbreak") — sandbox protections bypassed to run code on the host | Sandbox escape → RCE (CVSS 10.0; fixed 3.9.11) |

---