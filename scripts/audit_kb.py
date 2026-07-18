#!/usr/bin/env python3
"""Audit security-knowledge-bank: stats, broken links, duplicates."""
from __future__ import annotations

import json
import re
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def count_md(rel: str) -> int:
    p = ROOT / rel
    return len(list(p.rglob("*.md"))) if p.exists() else 0


def lang_stats() -> dict:
    out = {}
    for d in sorted((ROOT / "languages").iterdir()):
        if not d.is_dir():
            continue
        files = list(d.rglob("*.md"))
        has_check = any("hardening" in f.name or "checklist" in f.name for f in files)
        case = (
            len(list((d / "case-studies").rglob("*.md")))
            if (d / "case-studies").exists()
            else 0
        )
        other = [
            f
            for f in files
            if f.name != "index.md"
            and "case-studies" not in f.parts
            and "hardening" not in f.name
            and "checklist" not in f.name
        ]
        out[d.name] = {
            "total": len(files),
            "checklist": has_check,
            "cases": case,
            "docs": len(other),
        }
    return out


def find_broken_links() -> list[tuple[str, str]]:
    broken = []
    for d in ["common", "languages", "vibe-coding-specific", "resources"]:
        base = ROOT / d
        if not base.exists():
            continue
        for p in base.rglob("*.md"):
            text = p.read_text(encoding="utf-8", errors="replace")
            for link in re.findall(r"\]\(([^)]+\.md)\)", text):
                if link.startswith("http"):
                    continue
                # strip anchors
                link_path = link.split("#", 1)[0]
                target = (p.parent / link_path).resolve()
                if not target.exists():
                    rel = p.relative_to(ROOT).as_posix()
                    broken.append((rel, link))
    return broken


def find_case_dupes() -> list:
    """Heuristic: similar filenames under case-studies."""
    cases = [
        p
        for p in ROOT.rglob("*.md")
        if "case-studies" in p.parts
        and "embeddings" not in p.parts
        and p.parts[0] != "chunks"
    ]
    by_stem_key = defaultdict(list)
    for p in cases:
        key = re.sub(r"[^a-z0-9]+", "-", p.stem.lower())
        # collapse year-only differences partially
        key2 = re.sub(r"-20\d{2}-?", "-", key)
        key2 = re.sub(r"-+", "-", key2).strip("-")
        by_stem_key[key2].append(p.relative_to(ROOT).as_posix())
    return {k: v for k, v in by_stem_key.items() if len(v) > 1}


def main() -> None:
    langs = lang_stats()
    common = count_md("common")
    vibe = count_md("vibe-coding-specific")
    resources = count_md("resources")
    lang_total = count_md("languages")
    source = common + vibe + resources + lang_total
    cases = [
        p
        for p in ROOT.rglob("*.md")
        if "case-studies" in p.parts
        and "embeddings" not in p.parts
        and p.parts[0] != "chunks"
    ]
    emb = len(list((ROOT / "embeddings" / "chunks").glob("*.md"))) if (ROOT / "embeddings" / "chunks").exists() else 0
    ch = len(list((ROOT / "chunks").rglob("*.md"))) if (ROOT / "chunks").exists() else 0
    rules = 0
    for y in (ROOT / "semgrep-rules").glob("*.yml"):
        t = y.read_text(encoding="utf-8", errors="replace")
        rules += len(re.findall(r"(?m)^- id:", t))

    print("=== STATS ===")
    print(json.dumps({
        "source_md": source,
        "common": common,
        "languages": lang_total,
        "vibe": vibe,
        "resources": resources,
        "case_studies": len(cases),
        "embeddings_chunks": emb,
        "legacy_chunks": ch,
        "semgrep_rules": rules,
        "langs": langs,
    }, indent=2))

    broken = find_broken_links()
    print("=== BROKEN", len(broken), "===")
    for a, b in broken:
        print(f"  {a} -> {b}")

    dupes = find_case_dupes()
    print("=== CASE DUPES", len(dupes), "===")
    for k, v in sorted(dupes.items(), key=lambda x: -len(x[1]))[:30]:
        print(f"  {k}: {v}")


if __name__ == "__main__":
    main()
