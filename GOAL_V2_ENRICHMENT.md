# GOAL — Security Knowledge Bank v2 Enrichment

> **Usage:** Paste the entire contents of this file (or the `GOAL_COMMAND` block below) into a new Hermes session.  
> The agent should work end-to-end without needing conversation history.  
> **Target directory:** `C:\Users\muham\security-knowledge-bank\`

---

## GOAL_COMMAND (copy-paste)

```
GOAL: Enrich the Vibe Coding Security Knowledge Bank in C:\Users\muham\security-knowledge-bank\ to v2 level. Execute in order L1→L3→L2→L4; verify after each phase; when done, git commit + brief Turkish report.

CONTEXT:
- Repo already exists: README, index.md/html, 13 languages, common/, vibe-coding-specific/, embeddings/chunks (1002, severity unknown=0), semgrep-rules (79 API-level), scripts/audit_kb.py + maintain_kb.py + generate_quality_semgrep.py, _archive/legacy-chunks/, git master.
- User: Enes. Response in Turkish, direct, technical. Do NOT use Computer Use — terminal/CLI/web_search/web_extract. Claims must be verified from the web (NVD, vendor advisory, OWASP, real post-mortem). Fabricated CVEs/cases FORBIDDEN.
- Pipeline preference: collect → verify → write → (if needed) chunk → Semgrep. Sub-agent writes may silently fail — VERIFY files on disk after each round.

CONSTRAINTS:
1) Do not delete/corrupt existing quality md files; expand or add new files.
2) For topics marked "planned" in the index, either write the file or leave as planned — broken link = 0 (scripts/audit_kb.py).
3) Every new vulnerability file minimum structure:
   - Severity + CWE (if possible)
   - Vulnerability explanation
   - How AI / vibe coding generates this
   - Vulnerable code + secure fix
   - Prevention checklist
   - Real CVEs / case refs with source URLs (must be web-verified)
   - Vibe-coding red flags
4) Case study format: what happened → root cause → how AI produces the same error → fix → source links.
5) Semgrep: literal tutorial snip copy FORBIDDEN; API/sink + pattern-not + metadata(cwe, kb_path). No emoji inside patterns.
6) Windows + git-bash; paths: C:/Users/muham/security-knowledge-bank or /c/Users/muham/...
7) python command: `python` (python3 not available). For large tasks, use delegate_task in parallel (max 3), providing path + format + language context.
8) Don't say "done" before completion: audit_kb.py broken=0, semgrep yml parse, new files on disk, index numbers updated.

══════════════════════════════════════
PHASE L1 — Planned / gap file fill
══════════════════════════════════════
Goal: Write high-value files that are planned or missing in the index.

MANDATORY minimum set (skip if exists, write if missing):
COMMON:
- common/websocket.md
- common/zero-day.md (n-day vs 0-day, patch lag, AI outdated advisory risk — do not write exploit PoC)

C/C++ (languages/c-cpp/):
- double-free.md, uninitialized-memory.md, type-confusion.md, insecure-random.md, modern-cpp-pitfalls.md

C# (languages/csharp/):
- crypto-pitfalls.md, unity-security.md, process-injection.md
  (jwt/cors already remapped to aspnet-* deep — if needed expand the deep file, don't create empty stubs)

PHP: crypto-misuse.md
RUBY: session-security.md, redos.md, symbol-dos.md, idor-rails.md
SOLIDITY: integer-overflow.md, access-control.md, front-running.md, dos-gas.md, unchecked-calls.md, weak-randomness.md, delegatecall-proxy.md
KOTLIN: data-class-copy.md, spring-kotlin-misconfig.md (if coroutine/compose existing deep is linked, expand)
SWIFT: if planned maps to ios-security-deep/keychain, separate file not required; if gap exists, data-storage or certificate-pinning short doc

Each language index.md: planned → actual link; update or clear "Planned / Missing" section.
common/index.md same.

Verify L1:
- python scripts/audit_kb.py → BROKEN 0
- New files non-empty (>2KB preferred; do not accept template <500B)
- git commit: "content(L1): fill planned vulnerability docs"

══════════════════════════════════════
PHASE L3 — Semgrep quality expand (taint + framework)
══════════════════════════════════════
Goal: Increase 79 rules to ~120–180 with quality (no number padding).

Do:
1) Expand scripts/generate_quality_semgrep.py OR add new packs under semgrep-rules/:
   - vibe-taint-python.yml (optional mode: taint — if semgrep supports taint)
   - framework sinks: Django raw SQL / mark_safe, Flask debug, Express res.send+innerHTML, Spring SpEL/ObjectInputStream, EF FromSqlRaw, React dangerouslySetInnerHTML, subprocess shell=True, yaml.load, pickle, child_process.exec, BinaryFormatter, gets/strcpy, unserialize, YAML.load, tx.origin
2) paths.exclude: test/, tests/, *_test.py, vendor/, node_modules/, .venv/
3) metadata: cwe, kb_path, likelihood/impact or vibe-coding: true
4) metadata.json total_rules update
5) Small smoke: write temp vulnerable snippet files; run semgrep if installed; if not, YAML structural validate + pattern sanity (no emoji, id unique)

Verify L3:
- No id conflicts
- All yml rules start with via python -c, - id: count == metadata
- commit: "feat(L3): expand semgrep taint/framework rules"

══════════════════════════════════════
PHASE L2 — Deepen weak languages
══════════════════════════════════════
Goal: Bring TypeScript, Solidity, Ruby (+ optionally Kotlin/Swift) layer closer to Python/JS level.

TYPESCRIPT (languages/typescript/):
- nestjs-security.md or next-typescript-security.md
- zod-validation-bypass.md (type vs runtime)
- trpc-or-graphql-typed-trust.md (optional)
- 2024-2026 CVE roundup (verified)
- Update index + hardening-checklist

SOLIDITY:
- If L1 files are deep, OK; if not, cross-ref with reentrancy/flash-loan
- swc registry map table
- at least 1 new case study (verified, not duplicate)

RUBY:
- Expand rails-security.md OR active-record-secrets.md
- L1 files should be filled
- at least 1 new/reinforced case

KOTLIN/SWIFT: L1 gaps closed + index consistent

Verify L2:
- audit_kb.py BROKEN 0
- languages/typescript >= 10 md; keep no planned links for ruby/solidity
- commit: "content(L2): deepen typescript/solidity/ruby"

══════════════════════════════════════
PHASE L4 — Re-chunk + metadata ontology
══════════════════════════════════════
Goal: Reflect new/changed source md files into embeddings.

1) Update source → embeddings/chunks via process_embeddings.py (or maintain)
   - Processing only changed files is OK; full rebuild is also OK
2) severity regex fallback (unknown forbidden)
3) Enrich tags: cwe-id, vibe-red-flag, framework
4) Rebuild manifest.json
5) scripts/audit or verify_embeddings.py
6) Update index.md + index.html + README statistics to REAL numbers (source_md, cases, chunks, rules, size)
7) Do not touch _archive/legacy-chunks (canonical embeddings/chunks)

Verify L4:
- embeddings/chunks count consistent; unknown severity = 0
- audit_kb.py clean
- commit: "chore(L4): rechunk embeddings + refresh indexes"

══════════════════════════════════════
FINAL
══════════════════════════════════════
1) python scripts/audit_kb.py (full stats dump)
2) git log --oneline -10
3) Turkish report:
   - number of files added / path list (summary)
   - semgrep old→new rule count
   - chunk count + severity dist
   - remaining known gaps (if any)
   - how to use (semgrep config path, embeddings path)
4) Do NOT push remote (unless user requests).

SUCCESS CRITERIA:
- [ ] BROKEN links = 0
- [ ] L1 planned critical set files on disk and populated
- [ ] Semgrep >= 120 quality rules OR justified lower bound + taint/framework coverage
- [ ] TS/Ruby/Solidity notably deeper
- [ ] embeddings unknown severity = 0; manifest current
- [ ] index/README numbers correct
- [ ] at least 4 meaningful git commits (L1/L3/L2/L4)

START: First get baseline with python scripts/audit_kb.py; open todo list; start from L1.
```

---

## Short alias (single line)

```
GOAL: C:\Users\muham\security-knowledge-bank v2 enrichment — L1 planned fill → L3 semgrep taint/framework → L2 TS/Solidity/Ruby deepen → L4 rechunk+index sync. Details: GOAL_COMMAND inside security-knowledge-bank/GOAL_V2_ENRICHMENT.md. Turkish report, web-verified content, broken link 0, no fabricated CVE, no computer_use.
```

---

## Notes

| | |
|--|--|
| Execution | Paste the `GOAL_COMMAND` block into a new chat |
| Parallel | Use `delegate_task` for 3-way batch of L1 languages |
| Stopping | If user says "stop," commit the current phase, don't leave it unfinished |
| If semgrep not available | YAML validation is sufficient; CLI optional |
