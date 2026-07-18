---
source: "common/database/postgresql-mysql-security.md"
title: "PostgreSQL & MySQL Security for AI-Generated Applications"
heading: "6. Real CVEs (Web-Verified from NVD)"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [code, common-vuln, database-specific, explanation, hardening, secure, vulnerability, vulnerable]
chunk: 7/10
---

## 6. Real CVEs (Web-Verified from NVD)

### CVE-2024-10979 — PostgreSQL PL/Perl Environment Variable Hijacking
- **CVSS 3.1:** 8.8 (HIGH)
- **Published:** 2024-11-14
- **NVD Link:** https://nvd.nist.gov/vuln/detail/CVE-2024-10979
- **Description:** Incorrect control of environment variables in PostgreSQL PL/Perl allows an unprivileged database user to change sensitive process environment variables (e.g., PATH). This often suffices to enable arbitrary code execution, even if the attacker lacks a database server operating system user. Affects versions before 17.1, 16.5, 15.9, 14.14, 13.17, and 12.21.
- **CWE:** CWE-15 (External Control of System or Configuration Setting), CWE-610 (Externally Controlled Reference)
- **Relevance to AI-Generated Apps:** AI models frequently enable PL/Perl or PL/Python for "data processing" without understanding the security boundary implications.

### CVE-2024-7348 — PostgreSQL pg_dump TOCTOU Race Condition
- **CVSS 3.1:** 8.8 (HIGH) / 7.5 (HIGH)
- **Published:** 2024-08-08
- **NVD Link:** https://nvd.nist.gov/vuln/detail/CVE-2024-7348
- **Description:** Time-of-check Time-of-use (TOCTOU) race condition in pg_dump allows an object creator to execute arbitrary SQL functions as the user running pg_dump, which is often a superuser. Affects versions before 16.4, 15.8, 14.13, 13.16, and 12.20.
- **CWE:** CWE-367 (TOCTOU Race Condition)
- **Relevance to AI-Generated Apps:** AI-generated backup scripts often run pg_dump as superuser, and the generated code may not follow least-privilege backup practices.

### CVE-2024-32655 — Npgsql (PostgreSQL .NET Provider) Integer Overflow → SQL Injection
- **CVSS 3.1:** 8.1 (HIGH)
- **Published:** 2024-05-14
- **NVD Link:** https://nvd.nist.gov/vuln/detail/CVE-2024-32655
- **Description:** Integer overflow in Npgsql's `WriteBind()` method allows attackers to inject arbitrary PostgreSQL protocol messages, leading to execution of arbitrary SQL statements. Fixed in versions 4.0.14, 4.1.13, 5.0.18, 6.0.11, 7.0.7, and 8.0.3.
- **CWE:** CWE-89 (SQL Injection), CWE-190 (Integer Overflow)
- **Relevance to AI-Generated Apps:** AI-generated .NET applications often use Npgsql without checking version or applying security patches. A model trained before mid-2024 would not know about this vulnerability.

### CVE-2024-36039 — PyMySQL SQL Injection via Untrusted JSON
- **CVSS 3.1:** 6.3 (MEDIUM)
- **Published:** 2024-05-21
- **NVD Link:** https://nvd.nist.gov/vuln/detail/CVE-2024-36039
- **Description:** PyMySQL through version 1.1.0 allows SQL injection if used with untrusted JSON input because keys are not escaped by `escape_dict`. Fixed in version 1.1.1.
- **CWE:** CWE-89 (SQL Injection)
- **Relevance to AI-Generated Apps:** AI-generated Python code commonly uses `escape_dict()` (or the MySQL `escape()` function) from PyMySQL incorrectly, believing it sanitizes input when it does not.

### CVE-2024-5753 — Vanna AI SQL Injection (AI-Generated SQL Context)
- **CVSS 3.0:** 7.5 (HIGH)
- **Published:** 2024-07-05
- **NVD Link:** https://nvd.nist.gov/vuln/detail/CVE-2024-5753
- **Description:** Vanna AI (text-to-SQL library) version v0.3.4 is vulnerable to SQL injection via `pg_read_file()`, allowing unauthenticated remote attackers to read arbitrary local files.
- **CWE:** CWE-89 (SQL Injection)
- **Relevance to AI-Generated Apps:** This CVE directly demonstrates the risk of AI-generated SQL queries — the text-to-SQL pipeline itself becomes an injection vector. Applications that use LLMs to generate SQL must treat the output as untrusted.

### CVE-2024-5565 — Vanna AI Prompt Injection Leading to RCE
- **CVSS 3.1:** 8.1 (HIGH)
- **Published:** 2024-05-31
- **NVD Link:** https://nvd.nist.gov/vuln/detail/CVE-2024-5565
- **Description:** The Vanna AI library allows prompt injection to run arbitrary Python code instead of intended visualization code. External input to the "ask" method with `visualize=True` leads to remote code execution.
- **CWE:** CWE-94 (Code Injection)
- **Relevance to AI-Generated Apps:** Demonstrates how text-to-SQL pipelines compound risk — SQL injection + code injection in a single AI-generated tool.

### CVE-2024-20960 — MySQL Server
- **CVSS 3.1:** 6.5 (MEDIUM) — NVD (AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H, availability-only DoS)
- **Published:** 2024-04-16 (Oracle CPU)
- **NVD Link:** https://nvd.nist.gov/vuln/detail/CVE-2024-20960
- **Description:** Easily exploitable vulnerability allows low-privileged attacker with network access via multiple protocols to compromise MySQL Server. Successful attacks can result in unauthorized ability to cause a hang or frequently repeatable crash (complete DOS) of MySQL Server.
- **Relevance to AI-Generated Apps:** AI-generated applications frequently use older MySQL connectors and may miss critical patch levels.

---