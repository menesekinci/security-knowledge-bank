---
source: "languages/python/eval-exec.md"
title: "eval(), exec(), compile() Dangers"
heading: "Real-World CVEs"
category: "language-vuln"
language: "python"
severity: "critical"
tags: [checklist, code, cves, explanation, language-vuln, prevention, python, real-world, secure, vulnerability]
chunk: 6/7
---

## Real-World CVEs

| CVE | Description | Impact |
|---|---|---|
| **CVE-2024-6982** | RCE via `eval()` in parisneo/lollms | AI chat platform — eval injection in LLM tool calling |
| **CVE-2024-46946** | Langchain-experimental RCE via code injection | AI framework — exec used in SQL agent |
| **CVE-2024-45848** | MindsDB eval injection via ChromaDB integration | AI database platform |
| **CVE-2024-45595** | D-Tale eval injection in chart filter | Data science tool — eval(user_input) |
| **CVE-2024-41148** | ROS `rostopic` eval injection | Robotics — code injection via eval |

---