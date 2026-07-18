#!/usr/bin/env python3
"""
KB maintenance pass:
1) Fix broken relative links in index files (drop dead links → Planned section)
2) Deduplicate obvious case-study twins (keep larger file)
3) Severity backfill for embeddings chunks + manifest
4) Archive legacy chunks/ → _archive/legacy-chunks/
"""
from __future__ import annotations

import json
import re
import shutil
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# Map broken → existing equivalent when possible
LINK_REMAP: dict[str, dict[str, str]] = {
    "languages/csharp/index.md": {
        "jwt-auth.md": "aspnet-auth-deep.md",
        "cors-misconfig.md": "aspnet-misconfig.md",
        "crypto-pitfalls.md": None,  # planned
        "unity-security.md": None,
        "process-injection.md": None,
    },
    "languages/swift/index.md": {
        "data-storage.md": "keychain-storage.md",
        "ats-misconfig.md": "ios-security-deep.md",
        "webview-security.md": "ios-security-deep.md",
        "jailbreak-bypass.md": "ios-security-deep.md",
        "certificate-pinning.md": "ios-security-deep.md",
        "codable-pitfalls.md": "swiftui-security.md",
    },
    "languages/kotlin/index.md": {
        "coroutine-security.md": "android-security-deep.md",
        "compose-security.md": "jetpack-security.md",
        "data-class-copy.md": None,
        "spring-kotlin-misconfig.md": None,
    },
}


def fix_index_file(path: Path) -> tuple[int, int]:
    """Fix broken .md links in a single index. Returns (remapped, planned)."""
    text = path.read_text(encoding="utf-8")
    rel = path.relative_to(ROOT).as_posix()
    remapped = 0
    planned: list[tuple[str, str]] = []  # (title, filename)

    def repl(m: re.Match) -> str:
        nonlocal remapped
        full = m.group(0)
        title = m.group(1)
        link = m.group(2)
        if link.startswith("http") or not link.endswith(".md"):
            return full
        link_path = link.split("#", 1)[0]
        target = (path.parent / link_path).resolve()
        if target.exists():
            return full
        # remap table
        remap = LINK_REMAP.get(rel, {}).get(link_path)
        if remap:
            new_target = path.parent / remap
            if new_target.exists():
                remapped += 1
                return f"[{title}]({remap})"
        planned.append((title, link_path))
        # keep plain text (no dead link)
        return f"**{title}** _(planned)_"

    new_text = re.sub(r"\[([^\]]+)\]\(([^)]+\.md)\)", repl, text)

    if planned:
        # append planned section if not already there
        if "## 📝 Planned / Eksik Dosyalar" not in new_text and "## Planned" not in new_text:
            lines = ["", "---", "", "## 📝 Planned / Eksik Dosyalar", ""]
            lines.append("Aşağıdaki konular index'te referanslandı ama henüz ayrı dosya yok:")
            lines.append("")
            for title, fname in planned:
                lines.append(f"- {title} → `{fname}`")
            lines.append("")
            new_text = new_text.rstrip() + "\n" + "\n".join(lines)

    if new_text != text:
        path.write_text(new_text, encoding="utf-8", newline="\n")
    return remapped, len(planned)


def fix_all_indexes() -> None:
    total_remap = total_plan = 0
    for d in ["common", "languages", "vibe-coding-specific", "resources"]:
        base = ROOT / d
        if not base.exists():
            continue
        for p in base.rglob("index.md"):
            r, pl = fix_index_file(p)
            total_remap += r
            total_plan += pl
            if r or pl:
                print(f"  fixed {p.relative_to(ROOT)} remap={r} planned={pl}")
    print(f"Indexes: remapped={total_remap} planned_marked={total_plan}")


def dedupe_case_studies() -> None:
    """Remove shorter twin files for known duplicate pairs."""
    pairs = [
        (
            ROOT / "common/case-studies/notpetya-2017-supply-chain.md",
            ROOT / "common/case-studies/notpetya-supply-chain-attack.md",
        ),
        (
            ROOT / "common/case-studies/solarwinds-2020-supply-chain.md",
            ROOT / "common/case-studies/solarwinds-supply-chain-attack.md",
        ),
        (
            ROOT / "languages/c-cpp/case-studies/heartbleed-2014-openssl.md",
            ROOT / "languages/c-cpp/case-studies/heartbleed-openssl-cve-2014-0160.md",
        ),
        (
            ROOT / "languages/java/case-studies/equifax-2017-struts-deserialization.md",
            ROOT / "languages/java/case-studies/equifax-breach-apache-struts.md",
        ),
        (
            ROOT / "languages/java/case-studies/log4shell-2021-log4j.md",
            ROOT / "languages/java/case-studies/log4shell-cve-2021-44228.md",
        ),
        (
            ROOT / "languages/csharp/case-studies/talktalk-sql-injection-breach-2015.md",
            ROOT / "common/case-studies/talktalk-sql-injection-breach.md",
        ),
    ]
    removed = []
    for a, b in pairs:
        if not a.exists() or not b.exists():
            continue
        # keep larger
        keep, drop = (a, b) if a.stat().st_size >= b.stat().st_size else (b, a)
        # for talktalk keep both if different scopes? No — keep common one, drop csharp copy if smaller/same topic
        drop.unlink()
        removed.append(drop.relative_to(ROOT).as_posix())
        print(f"  dedupe keep={keep.relative_to(ROOT)} drop={drop.relative_to(ROOT)}")
    print(f"Deduped {len(removed)} files")


SEV_PATTERNS = [
    (re.compile(r"(?i)\*\*severity:\*\*\s*(critical|kritik)", re.I), "critical"),
    (re.compile(r"(?i)\*\*severity:\*\*\s*(high|yüksek)", re.I), "high"),
    (re.compile(r"(?i)\*\*severity:\*\*\s*(medium|orta)", re.I), "medium"),
    (re.compile(r"(?i)\*\*severity:\*\*\s*(low|düşük)", re.I), "low"),
    (re.compile(r"(?i)severity[:\s]+\*?\*?(critical|kritik)"), "critical"),
    (re.compile(r"(?i)severity[:\s]+\*?\*?(high|yüksek)"), "high"),
    (re.compile(r"(?i)severity[:\s]+\*?\*?(medium|orta)"), "medium"),
    (re.compile(r"🔴\s*(Kritik|Critical)"), "critical"),
    (re.compile(r"🟠\s*(Yüksek|High)"), "high"),
    (re.compile(r"🟡\s*(Orta|Medium)"), "medium"),
    (re.compile(r"CVSS[:\s]*9\.\d|CVSS[:\s]*10"), "critical"),
    (re.compile(r"CVSS[:\s]*[7-8]\."), "high"),
    (re.compile(r"CVSS[:\s]*[4-6]\."), "medium"),
    (re.compile(r"(?i)\b(rce|remote code execution|deserialization rce)\b"), "critical"),
    (re.compile(r"(?i)\b(sql injection|sqli|command injection|ssrf|xss)\b"), "high"),
    (re.compile(r"(?i)\b(case study|breach|incident)\b"), "high"),
    (re.compile(r"(?i)\b(checklist|hardening|prevention)\b"), "medium"),
    (re.compile(r"(?i)\b(overview|intro|index)\b"), "medium"),
]

# path-based severity hints
PATH_SEV = [
    (re.compile(r"(?i)(rce|injection|overflow|deserialization|reentrancy|log4shell|pickle|eval)"), "critical"),
    (re.compile(r"(?i)(ssrf|xss|csrf|auth|jwt|supply-chain|path-traversal)"), "high"),
    (re.compile(r"(?i)(checklist|hardening|logging|misconfig)"), "medium"),
]


def detect_severity(text: str, source: str = "", heading: str = "") -> str:
    head = text[:3000]
    for pat, sev in SEV_PATTERNS:
        if pat.search(head):
            return sev
    blob = f"{source} {heading} {text[:500]}"
    for pat, sev in PATH_SEV:
        if pat.search(blob):
            return sev
    return "medium"  # default better than unknown for RAG filtering


def parse_frontmatter(content: str) -> tuple[dict, str]:
    if not content.startswith("---"):
        return {}, content
    end = content.find("\n---", 3)
    if end == -1:
        return {}, content
    fm_raw = content[3:end].strip()
    body = content[end + 4 :].lstrip("\n")
    meta = {}
    for line in fm_raw.splitlines():
        if ":" not in line:
            continue
        k, v = line.split(":", 1)
        k = k.strip()
        v = v.strip().strip('"').strip("'")
        meta[k] = v
    return meta, body


def render_frontmatter(meta: dict) -> str:
    order = [
        "source",
        "title",
        "heading",
        "category",
        "language",
        "severity",
        "tags",
        "chunk",
    ]
    lines = ["---"]
    seen = set()
    for k in order:
        if k not in meta:
            continue
        seen.add(k)
        v = meta[k]
        if k == "tags" and isinstance(v, str) and v.startswith("["):
            lines.append(f"{k}: {v}")
        elif isinstance(v, list):
            lines.append(f"{k}: [{', '.join(str(x) for x in v)}]")
        else:
            escaped = str(v).replace('"', "'")
            if k == "chunk" and "/" in str(v):
                lines.append(f"{k}: {v}")
            else:
                lines.append(f'{k}: "{escaped}"')
    for k, v in meta.items():
        if k in seen:
            continue
        escaped = str(v).replace('"', "'")
        lines.append(f'{k}: "{escaped}"')
    lines.append("---")
    return "\n".join(lines)


def severity_backfill() -> None:
    chunk_dir = ROOT / "embeddings" / "chunks"
    manifest_path = ROOT / "embeddings" / "manifest.json"
    if not chunk_dir.exists():
        print("No embeddings/chunks")
        return

    counts = Counter()
    updated_files = 0
    entries = []

    for p in sorted(chunk_dir.glob("*.md")):
        raw = p.read_text(encoding="utf-8", errors="replace")
        meta, body = parse_frontmatter(raw)
        old = (meta.get("severity") or "unknown").lower()
        if old in ("", "unknown", "n/a", "none"):
            new = detect_severity(
                body,
                source=meta.get("source", p.name),
                heading=meta.get("heading", meta.get("title", "")),
            )
            meta["severity"] = new
            new_raw = render_frontmatter(meta) + "\n\n" + body.lstrip()
            if not new_raw.endswith("\n"):
                new_raw += "\n"
            p.write_text(new_raw, encoding="utf-8", newline="\n")
            updated_files += 1
            counts[new] += 1
            sev = new
        else:
            counts[old] += 1
            sev = old

        # rebuild manifest entry
        entries.append(
            {
                "file": p.name,
                "source": meta.get("source", ""),
                "chunks": None,
                "chunk": meta.get("chunk", ""),
                "heading": meta.get("heading", ""),
                "category": meta.get("category", ""),
                "language": meta.get("language", ""),
                "severity": sev,
            }
        )

    # fill chunks count per source
    by_src = Counter(e["source"] for e in entries)
    for e in entries:
        e["chunks"] = by_src[e["source"]]

    manifest_path.write_text(
        json.dumps(entries, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    print(f"Severity backfill: updated_files={updated_files}")
    print(f"  distribution: {dict(counts)}")
    print(f"  manifest entries: {len(entries)}")


def archive_legacy_chunks() -> None:
    src = ROOT / "chunks"
    if not src.exists():
        print("No legacy chunks/")
        return
    dest = ROOT / "_archive" / "legacy-chunks"
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.exists():
        print("Archive already exists, skip move")
        return
    shutil.move(str(src), str(dest))
    # pointer readme
    note = ROOT / "_archive" / "README.md"
    note.write_text(
        "# Archive\n\n"
        "`legacy-chunks/` — older intermediate chunk set (334 files).\n"
        "Canonical embedding chunks live in `embeddings/chunks/` (1002 files).\n",
        encoding="utf-8",
        newline="\n",
    )
    print(f"Moved chunks/ → {dest.relative_to(ROOT)}")


def main() -> None:
    print("=== 1. Fix indexes ===")
    fix_all_indexes()
    print("=== 2. Dedupe case studies ===")
    dedupe_case_studies()
    print("=== 3. Severity backfill ===")
    severity_backfill()
    print("=== 4. Archive legacy chunks ===")
    archive_legacy_chunks()
    print("DONE")


if __name__ == "__main__":
    main()
