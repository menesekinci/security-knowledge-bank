---
source: "common/injection.md"
title: "Injection Vulnerabilities (SQL, NoSQL, OS Command, LDAP, Expression Language)"
heading: "What Is Injection?"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [command, common-vuln, injection, nosql, vibe, what]
chunk: 2/11
---

## What Is Injection?

Injection occurs when **untrusted user data is sent to an interpreter** (SQL database, OS shell, LDAP directory, expression parser) as part of a command or query. The attacker's data tricks the interpreter into executing unintended commands or accessing unauthorized data.

**The core rule:** Injection is always a **data vs. code separation** problem. When user input is concatenated directly into a command string, the interpreter can't tell where the developer's code ends and the attacker's data begins.