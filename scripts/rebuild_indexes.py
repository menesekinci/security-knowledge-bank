#!/usr/bin/env python3
"""Rebuild language/common index TOCs from filesystem; strip Planned if files exist."""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def list_md(lang_dir: Path) -> list[str]:
    files = []
    for p in sorted(lang_dir.glob("*.md")):
        if p.name == "index.md":
            continue
        files.append(p.name)
    return files


def patch_index(path: Path) -> None:
    if not path.exists():
        return
    text = path.read_text(encoding="utf-8")
    # Remove Planned sections entirely
    text2 = re.sub(
        r"\n---\n\n## 📝 Planned / Eksik Dosyalar\n.*?\Z",
        "\n",
        text,
        flags=re.S,
    )
    # If planned markers remain as bold _(planned)_, leave content; links should exist
    if text2 != text:
        path.write_text(text2.rstrip() + "\n", encoding="utf-8", newline="\n")
        print("stripped planned:", path.relative_to(ROOT))


def rewrite_lang_index(lang: str, title: str, intro_lines: list[str], items: list[tuple[str, str]]) -> None:
    """items: (emoji_severity_label, filename)"""
    path = ROOT / "languages" / lang / "index.md"
    existing = list_md(ROOT / "languages" / lang)
    lines = [f"# {title}", ""]
    lines.extend(intro_lines)
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## 📋 İçindekiler")
    lines.append("")
    n = 1
    for label, fname in items:
        if fname not in existing and not (ROOT / "languages" / lang / fname).exists():
            continue
        lines.append(f"{n}. [{label}]({fname})")
        n += 1
    # auto-append any extra md not listed
    listed = {f for _, f in items}
    for fname in existing:
        if fname in listed:
            continue
        if fname.startswith("2024") or "roundup" in fname:
            lines.append(f"{n}. [CVE Roundup]({fname})")
        elif "hardening" in fname:
            lines.append(f"{n}. [Hardening Checklist]({fname})")
        else:
            lines.append(f"{n}. [{fname}]({fname})")
        n += 1
    if (ROOT / "languages" / lang / "case-studies").is_dir():
        lines.append(f"{n}. [Case Studies](case-studies/)")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append(f"*Auto-refreshed index — files on disk: {len(existing)}*")
    lines.append("")
    path.write_text("\n".join(lines), encoding="utf-8", newline="\n")
    print("rewrote", path.relative_to(ROOT))


def main() -> None:
    # strip planned sections everywhere
    for p in (ROOT / "common").rglob("index.md"):
        patch_index(p)
    for p in (ROOT / "languages").rglob("index.md"):
        patch_index(p)

    # common index — ensure websocket/zero-day linked
    cidx = ROOT / "common" / "index.md"
    t = cidx.read_text(encoding="utf-8")
    t = t.replace("**WebSocket Security** _(planned)_ → `websocket.md`", "[🟡 WebSocket Security](websocket.md)")
    t = t.replace("**Zero-Day / N-Day Exploits** _(planned)_ → `zero-day.md`", "[🔴 Zero-Day / N-Day Exploits](zero-day.md)")
    t = re.sub(r"\n---\n\n## 📝 Planned / Eksik Dosyalar\n.*", "\n", t, flags=re.S)
    cidx.write_text(t.rstrip() + "\n", encoding="utf-8", newline="\n")
    print("fixed common/index.md links")

    rewrite_lang_index(
        "c-cpp",
        "⚙️ C/C++ Security",
        ["> Memory safety and low-level pitfalls for vibe coding.", ""],
        [
            ("🔴 Buffer Overflow", "buffer-overflow.md"),
            ("🔴 Use-After-Free", "use-after-free.md"),
            ("🔴 Format String", "format-string.md"),
            ("🟠 Integer Overflow", "integer-overflow.md"),
            ("🟠 Null Pointer", "null-pointer.md"),
            ("🟠 Double Free", "double-free.md"),
            ("🟠 Uninitialized Memory", "uninitialized-memory.md"),
            ("🟠 Type Confusion", "type-confusion.md"),
            ("🟡 Insecure Random", "insecure-random.md"),
            ("🟡 Race Conditions", "race-conditions.md"),
            ("🟡 Modern C++ Pitfalls", "modern-cpp-pitfalls.md"),
            ("🔴 Unsafe Functions", "unsafe-functions.md"),
            ("🟡 constexpr Security", "constexpr-security.md"),
            ("🔴 Coroutine Security", "coroutine-security.md"),
            ("🔴 VTable Hijacking", "vtable-hijacking.md"),
            ("🛡️ Hardening Checklist", "hardening-checklist.md"),
        ],
    )

    rewrite_lang_index(
        "csharp",
        "💠 C# / .NET Security",
        ["> ASP.NET, Blazor, and .NET vibe-coding traps.", ""],
        [
            ("🔴 Deserialization", "deserialization.md"),
            ("🔴 SQL Injection / EF", "sql-injection-ef.md"),
            ("🟠 ASP.NET Misconfig", "aspnet-misconfig.md"),
            ("🟠 XXE", "xxe-attacks.md"),
            ("🟠 ASP.NET Auth Deep", "aspnet-auth-deep.md"),
            ("🟠 ASP.NET Data Protection", "aspnet-data-protection.md"),
            ("🔴 LINQ Injection", "linq-injection.md"),
            ("🟡 Crypto Pitfalls", "crypto-pitfalls.md"),
            ("🟡 NuGet Supply Chain", "nuget-supply-chain.md"),
            ("🔴 Blazor Security", "blazor-security.md"),
            ("🟡 Unity Security", "unity-security.md"),
            ("🔴 Process Injection", "process-injection.md"),
            ("🟡 Roslyn Security", "dotnet-roslyn-security.md"),
            ("🚨 CVE Roundup", "2024-cve-roundup-dotnet.md"),
            ("🛡️ Hardening Checklist", "hardening-checklist.md"),
        ],
    )

    rewrite_lang_index(
        "ruby",
        "💎 Ruby Security",
        ["> Rails and Ruby ecosystem vibe-coding traps.", ""],
        [
            ("🔴 YAML.load RCE", "yaml-deserialization.md"),
            ("🔴 Mass Assignment", "mass-assignment.md"),
            ("🟠 SQL Injection", "sql-injection.md"),
            ("🟠 Command Injection", "command-injection.md"),
            ("🟠 Session Security", "session-security.md"),
            ("🟡 ReDoS", "redos.md"),
            ("🟡 Symbol DoS", "symbol-dos.md"),
            ("🟡 IDOR Rails", "idor-rails.md"),
            ("🔴 Rails Security", "rails-security.md"),
            ("🛡️ Hardening Checklist", "hardening-checklist.md"),
        ],
    )

    rewrite_lang_index(
        "solidity",
        "🔷 Solidity / Blockchain Security",
        ["> Smart contract risks — bugs are irreversible value loss.", ""],
        [
            ("🔴 Reentrancy", "reentrancy.md"),
            ("🔴 Flash Loan", "flash-loan.md"),
            ("🔴 Oracle Manipulation", "oracle-manipulation.md"),
            ("🟠 tx.origin", "tx-origin.md"),
            ("🟠 Integer Overflow", "integer-overflow.md"),
            ("🟠 Access Control", "access-control.md"),
            ("🟠 Front-Running / MEV", "front-running.md"),
            ("🟡 DoS Gas", "dos-gas.md"),
            ("🟡 Unchecked Calls", "unchecked-calls.md"),
            ("🟡 Weak Randomness", "weak-randomness.md"),
            ("🟡 Delegatecall Proxy", "delegatecall-proxy.md"),
            ("🛡️ Hardening Checklist", "hardening-checklist.md"),
        ],
    )

    rewrite_lang_index(
        "kotlin",
        "🌊 Kotlin Security",
        ["> Android and Spring Kotlin vibe-coding traps.", ""],
        [
            ("🟡 Null Safety Bypass", "null-safety-bypass.md"),
            ("🟠 Android Keystore", "android-keystore.md"),
            ("🟠 Android Security Deep", "android-security-deep.md"),
            ("🟠 Jetpack Security", "jetpack-security.md"),
            ("🟠 Data Class copy()", "data-class-copy.md"),
            ("🟠 Spring Kotlin Misconfig", "spring-kotlin-misconfig.md"),
            ("🛡️ Hardening Checklist", "hardening-checklist.md"),
        ],
    )

    rewrite_lang_index(
        "php",
        "🐘 PHP Security",
        ["> Type juggling, unserialize, and framework traps.", ""],
        [
            ("🔴 Type Juggling", "type-juggling.md"),
            ("🔴 Unserialize RCE", "unserialize-rce.md"),
            ("🔴 LFI/RFI", "lfi-rfi.md"),
            ("🔴 SQL Injection", "sql-injection.md"),
            ("🟠 Command Injection", "command-injection.md"),
            ("🟠 File Upload", "file-upload-bypass.md"),
            ("🟠 Session Security", "session-security.md"),
            ("🟡 Crypto Misuse", "crypto-misuse.md"),
            ("🔴 Laravel", "laravel-security.md"),
            ("🔴 Symfony", "symfony-security.md"),
            ("🔴 WordPress", "wordpress-security.md"),
            ("🔴 PHAR Deserialization", "phar-deserialization.md"),
            ("🛡️ Hardening Checklist", "hardening-checklist.md"),
        ],
    )

    rewrite_lang_index(
        "typescript",
        "🔷 TypeScript Security",
        [
            "> Types are not a security boundary — runtime validation required.",
            "",
        ],
        [
            ("🟠 Type Safety Bypass", "type-safety-bypass.md"),
            ("🟡 Reflect Metadata", "reflect-metadata.md"),
            ("🟡 Decorator Abuse", "decorator-abuse.md"),
            ("🔴 Next.js + TypeScript", "next-typescript-security.md"),
            ("🔴 Zod Validation Bypass", "zod-validation-bypass.md"),
            ("🟠 NestJS Security", "nestjs-security.md"),
            ("🚨 CVE Roundup 2024-2026", "2024-2026-cve-roundup.md"),
            ("🛡️ Hardening Checklist", "hardening-checklist.md"),
        ],
    )

    print("done")


if __name__ == "__main__":
    main()
