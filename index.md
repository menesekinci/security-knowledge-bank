# 🔒 Vibe Coding Security Knowledge Bank

> **A security knowledge bank for AI-assisted (vibe) coding.**
> Language-specific pitfalls, cross-cutting vulnerabilities, real-world case studies, embedding chunks, and Semgrep rules.
> **Total: 364 source .md | 14 languages | 86 case studies | 1,551 embedding chunks | 155 Semgrep rules**

---

## 📂 Table of Contents

### 🧬 Common Vulnerabilities (Cross-Cutting)
→ [common/index.md](common/index.md) — injection, XSS, auth, SSRF, supply-chain, OAuth2, CORS/CSP, WebSocket, zero-day/n-day, API & cloud…

### 🌍 Case Studies
→ [common/case-studies/](common/case-studies/) + per-language `case-studies/` — **86** cases

### 🛡️ By Language

| Language | Files (approx) | Checklist |
|-----|---------------:|:---------:|
| [🐍 Python](languages/python/index.md) | 28 | ✅ |
| [🌐 JavaScript](languages/javascript/index.md) | 29 | ✅ |
| [☕ Java](languages/java/index.md) | 23 | ✅ |
| [🐘 PHP](languages/php/index.md) | 24 | ✅ |
| [💠 C# / .NET](languages/csharp/index.md) | 25 | ✅ |
| [⚙️ C/C++](languages/c-cpp/index.md) | 25 | ✅ |
| [🐹 Go](languages/go/index.md) | 22 | ✅ |
| [🦀 Rust](languages/rust/index.md) | 20 | ✅ |
| [🔷 TypeScript](languages/typescript/index.md) | 15 | ✅ |
| [💎 Ruby](languages/ruby/index.md) | 16 | ✅ |
| [🔷 Solidity](languages/solidity/index.md) | 17 | ✅ |
| [🌊 Kotlin](languages/kotlin/index.md) | 12 | ✅ |
| [🍎 Swift](languages/swift/index.md) | 10 | ✅ |
| [🎯 Dart / Flutter](languages/dart/index.md) | 3 | ✅ |

### 🤖 Vibe Coding Specific
→ [vibe-coding-specific/index.md](vibe-coding-specific/index.md) — **15 files**

### 🧩 Embeddings
→ `embeddings/chunks/` — **1,551** chunks · severity `unknown=0`
→ `embeddings/manifest.json`

### 🔍 Semgrep
→ [semgrep-rules/](semgrep-rules/) — **155** rules (API sinks + `vibe-framework.yml`)

```bash
semgrep --config semgrep-rules/ /path/to/repo
semgrep --config semgrep-rules/vibe-framework.yml .
```

### 🛠️ Scripts
| Script | Role |
|--------|-----|
| `scripts/audit_kb.py` | Stats + broken-link check |
| `scripts/maintain_kb.py` | Maintenance |
| `scripts/generate_l1_docs.py` | Planned-doc generator |
| `scripts/rebuild_indexes.py` | Index TOC rebuild |
| `scripts/expand_framework_semgrep.py` | Framework Semgrep pack |
| `scripts/process_embeddings.py` | Source → chunks |
| `GOAL_V2_ENRICHMENT.md` | v2 enrichment goal |

### 📦 Archive
→ `_archive/legacy-chunks/` — old legacy chunks (do not use)

---

## 📈 Statistics

| Metric | Value |
|--------|------:|
| Source `.md` | **364** |
| Case studies | **86** |
| Embedding chunks | **1,551** |
| Semgrep rules | **155** |
| Languages | **14** |
| Hardening checklists | **14** |

---

*v2 enrichment: L1 planned fill · L3 framework Semgrep · L2 TS/Ruby/Solidity · L4 rechunk*
