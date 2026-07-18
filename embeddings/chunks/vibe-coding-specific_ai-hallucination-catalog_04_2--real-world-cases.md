---
source: "vibe-coding-specific/ai-hallucination-catalog.md"
title: "🔴 AI Hallucination Catalog — Security Context"
heading: "2. Real World Cases"
category: "vibe-coding"
language: "common"
severity: "critical"
tags: [hallucination, real, references, table, types, vibe-coding, world]
chunk: 4/6
---

## 2. Real World Cases

### Case 1: AI Hallucination Package Supply Chain Attack

| Year | Event | Detail |
|------|-------|--------|
| 2023 | PyPI hallucination squatting | Researcher purchased PyPI package names that ChatGPT hallucinated. Packages were downloaded over 40,000 times. Source: [arXiv:2304.10477](https://arxiv.org/abs/2304.10477) |
| 2023 | Lemniscap npm study | 20% of AI-recommended npm packages do not actually exist. Source: Lemniscap Research |
| 2022 | Codex hallucination attacks | Aqua Security showed GitHub Copilot suggests non-existent libraries. Source: [Aqua Security Blog](https://www.aquasec.com/blog/codex-hallucination-attacks/) |

### Case 2: Security Vulnerabilities in AI-Generated Code

| Year | Event | Detail |
|------|-------|--------|
| 2023 | Stanford + IEEE Study | Rate of SQL injection, XSS and path traversal vulnerabilities in AI code generation — ChatGPT produced code with security vulnerabilities at 40%, GitHub Copilot at 35% |
| 2024 | JetBrains Research | 65% of developers using AI for code generation skip or reduce security testing |
| 2023 | Black Hat USA | More than 50% of encryption code produced by AI contains fundamental cryptographic errors |

### Case 3: Fake CVE and Alert Fatigue

| Year | Event | Detail |
|------|-------|--------|
| 2024 | Aqua Security CVE hallucination | 30-40% of CVE references produced by AI cannot be found in reality. This causes "alert fatigue" in security teams |
| 2023 | VulnCheck study | Fake CVE numbers fabricated by AI were detected in security advisories |

---