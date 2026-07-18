---
source: "resources/severity-matrix.md"
title: "🗺️ Vibe Coding Security — Severity Cross-Reference Matrix"
category: "resource"
language: "common"
severity: "critical"
tags: [biggest, critical, danger, language, most, resource, risky, vulnerability]
---

# 🗺️ Vibe Coding Security — Severity Cross-Reference Matrix

> How critical each vulnerability is in which languages.
> 🔴 = High risk due to language nature  |  🟡 = Low risk (language protects)

## Vulnerability × Language Matrix

| Vulnerability | Py | JS | TS | Rs | Go | Ja | C# | C++ | PHP | Rb | Sw | Kt | Sol |
|--------------|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|
| SQL Injection | 🔴 | 🟡 | 🟡 | 🟡 | 🔴 | 🔴 | 🔴 | 🟡 | 🔴 | 🔴 | 🟡 | 🟡 | 🟡 |
| XSS | 🟡 | 🔴 | 🔴 | 🟡 | 🟡 | 🟡 | 🟡 | 🟡 | 🔴 | 🟡 | 🟡 | 🟡 | 🟡 |
| Command Inj. | 🔴 | 🔴 | 🔴 | 🟡 | 🟡 | 🟡 | 🟡 | 🔴 | 🔴 | 🔴 | 🟡 | 🟡 | 🟡 |
| Deserialization | 🔴 | 🟡 | 🟡 | 🟡 | 🟡 | 🔴 | 🔴 | 🟡 | 🔴 | 🔴 | 🟡 | 🟡 | 🟡 |
| Buffer Overflow | 🟡 | 🟡 | 🟡 | 🟡 | 🟡 | 🟡 | 🟡 | 🔴 | 🟡 | 🟡 | 🟡 | 🟡 | 🟡 |
| Use-After-Free | 🟡 | 🟡 | 🟡 | 🟡 | 🟡 | 🟡 | 🟡 | 🔴 | 🟡 | 🟡 | 🟡 | 🟡 | 🟡 |
| Integer Overflow | 🟡 | 🟡 | 🟡 | 🟡 | 🔴 | 🟡 | 🟡 | 🔴 | 🟡 | 🟡 | 🟡 | 🟡 | 🔴 |
| Race Condition | 🔴 | 🟡 | 🟡 | 🟡 | 🔴 | 🔴 | 🔴 | 🔴 | 🟡 | 🟡 | 🟡 | 🟡 | 🔴 |
| SSRF | 🔴 | 🔴 | 🔴 | 🟡 | 🔴 | 🔴 | 🟡 | 🟡 | 🟡 | 🟡 | 🟡 | 🟡 | 🟡 |
| Path Traversal | 🔴 | 🟡 | 🟡 | 🟡 | 🔴 | 🔴 | 🔴 | 🟡 | 🔴 | 🟡 | 🟡 | 🟡 | 🟡 |
| Supply Chain | 🔴 | 🔴 | 🔴 | 🔴 | 🔴 | 🔴 | 🔴 | 🟡 | 🟡 | 🔴 | 🟡 | 🟡 | 🟡 |
| Crypto Failures | 🔴 | 🔴 | 🔴 | 🟡 | 🟡 | 🔴 | 🔴 | 🟡 | 🟡 | 🟡 | 🔴 | 🔴 | 🔴 |
| XXE | 🟡 | 🟡 | 🟡 | 🟡 | 🟡 | 🔴 | 🔴 | 🟡 | 🟡 | 🟡 | 🟡 | 🟡 | 🟡 |
| SSTI | 🔴 | 🟡 | 🟡 | 🟡 | 🟡 | 🔴 | 🟡 | 🟡 | 🔴 | 🟡 | 🟡 | 🟡 | 🟡 |
| Memory Safety | 🟡 | 🟡 | 🟡 | 🟡 | 🟡 | 🟡 | 🟡 | 🔴 | 🟡 | 🟡 | 🟡 | 🟡 | 🟡 |
| Auth Broken | 🔴 | 🔴 | 🔴 | 🟡 | 🔴 | 🔴 | 🔴 | 🟡 | 🔴 | 🔴 | 🔴 | 🔴 | 🔴 |
| Reentrancy | 🟡 | 🟡 | 🟡 | 🟡 | 🟡 | 🟡 | 🟡 | 🟡 | 🟡 | 🟡 | 🟡 | 🟡 | 🔴 |
| Prototype Poll. | 🟡 | 🔴 | 🔴 | 🟡 | 🟡 | 🟡 | 🟡 | 🟡 | 🟡 | 🟡 | 🟡 | 🟡 | 🟡 |
| IDOR | 🔴 | 🔴 | 🔴 | 🟡 | 🔴 | 🔴 | 🔴 | 🟡 | 🔴 | 🔴 | 🔴 | 🔴 | 🟡 |

## 🔴 Most Critical Combinations for Vibe Coding (Updated)

| # | Combination | Why It Blows Up in Vibe Coding |
|---|-------------|-------------------------------|
| 1 | **AI + PHP (Type Juggling)** | AI uses `==`, doesn't remember `===` |
| 2 | **AI + Python (Pickle/eval)** | AI suggests it as a "quick solution" |
| 3 | **AI + JS (npm Supply Chain)** | AI hallucinates and suggests packages |
| 4 | **AI + Java (Deserialization)** | AI produces old framework patterns |
| 5 | **AI + C/C++ (Buffer Overflow)** | AI skips boundary checks |
| 6 | **AI + Solidity (Reentrancy)** | AI does "send first, update later" |
| 7 | **AI + Cloud (Credential Leak)** | AI hardcodes instead of using env variables |
| 8 | **AI + GraphQL (Introspection)** | AI skips the security layer |

## Biggest Danger Per Language

| Language | AI's Most Common Mistake |
|----------|-------------------------|
| Python | `eval()` + `pickle.load()` + PyPI hallucination |
| JavaScript | `innerHTML` + prototype pollution + npm confusion |
| TypeScript | `as any` + `// @ts-ignore` bypassing type safety |
| Rust | Using `unsafe` blocks without justification |
| Go | `nil` pointer + race condition + `InsecureSkipVerify` |
| Java | Old Log4j version + SpEL injection + deserialization |
| C# | BinaryFormatter + LINQ injection + NuGet confusion |
| C/C++ | `gets()` + `printf(user)` + use after `free()` |
| PHP | Type juggling with `==` + `unserialize()` + `eval()` |
| Ruby | `YAML.load()` + mass assignment + backtick |
| Swift | `UserDefaults` + `!!` force unwrap + deep link |
| Kotlin | `!!` null bypass + SharedPrefs + implicit intent |
| Solidity | Reentrancy + tx.origin + oracle manipulation |

## Most Risky Languages for AI Vibe Coding

| Rank | Language | Why? |
|:----:|----------|------|
| 🥇 | **PHP** | AI produces old PHP patterns, type system is weak |
| 🥇 | **JavaScript** | npm supply chain + prototype pollution |
| 🥇 | **Python** | Pickle + eval + PyPI confusion |
| 🥈 | **C/C++** | Memory safety is the biggest thing AI misses |
| 🥈 | **Java** | Deserialization + supply chain like Log4j |
| 🥉 | **Solidity** | Every mistake = loss of money |
