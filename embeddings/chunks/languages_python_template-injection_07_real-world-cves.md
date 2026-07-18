---
source: "languages/python/template-injection.md"
title: "Template Injection (SSTI) — Jinja2, Mako, Django"
heading: "Real-World CVEs"
category: "language-vuln"
language: "python"
severity: "critical"
tags: [checklist, code, explanation, language-vuln, prevention, python, secure, vulnerability, vulnerable]
chunk: 7/8
---

## Real-World CVEs

| CVE | CVSS | Description | Impact |
|---|---|---|---|
| **CVE-2025-23211** | 9.9 | Jinja2 SSTI in Tandoor Recipes (< 1.5.24) — any user can run commands | Recipe app — full system compromise |
| **CVE-2025-66434** | 8.8 | Frappe ERPNext (≤ 15.89.0) SSTI in `get_dunning_letter_text` via `frappe.render_template()` | Enterprise ERP — RCE / DB leak |
| **CVE-2024-32651** | 10.0 | changedetection.io (≤ 0.45.20) Jinja2 SSTI — unrestricted remote command execution | Web monitoring tool — full RCE |
| **CVE-2024-34359** | 9.6 | llama-cpp-python (0.2.30–0.2.71) renders a `.gguf` model's chat template in a sandbox-less `jinja2.Environment` | Malicious model file → RCE |
| **CVE-2024-56201** | 8.8 | Jinja compiler bug — an attacker controlling both template content and filename runs arbitrary Python even under the sandbox (fixed 3.1.5) | Jinja core — sandbox bypass to RCE |
| **CVE-2024-56326** | 7.8 | Jinja sandbox escape — an oversight in how `str.format` calls are detected lets template content execute arbitrary Python (fixed 3.1.5) | Jinja core — sandbox escape |

---