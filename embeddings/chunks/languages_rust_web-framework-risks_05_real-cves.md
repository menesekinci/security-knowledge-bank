---
source: "languages/rust/web-framework-risks.md"
title: "Web Framework Risks — Actix, Axum, Rocket Common Misconfigurations"
heading: "Real CVEs"
category: "language-vuln"
language: "rust"
severity: "high"
tags: [checklist, common, cross-framework, cves, framework-specific, language-vuln, overview, prevention, real, risks]
chunk: 5/6
---

## Real CVEs

- **CVE-2023-44487 (HTTP/2 Rapid Reset)**: All Rust web frameworks using `hyper` or `h2` were affected. A client opens many HTTP/2 streams and immediately sends `RST_STREAM` for each, forcing costly server-side work at near-zero client cost. A protocol-level bug, not Rust-specific (CVSS 7.5), but it shows Rust web apps are not immune to high-severity CVEs.
- **CVE-2024-32650 / RUSTSEC-2024-0336 (rustls infinite-loop DoS)**: On a **blocking** rustls server, if a client sends `close_notify` right after `client_hello`, `ConnectionCommon::complete_io` never terminates — the thread spins at 100% CPU. A handful of such connections can starve a multithreaded (non-async) TLS server. CVSS 7.5. Affects rustls ≤ 0.23.4 (and 0.20–0.22 lines); fixed in 0.23.5 / 0.22.4 / 0.21.11. `rustls-tokio` async servers are not affected.
- **RUSTSEC-2023-0071 / CVE-2023-49092 (Marvin timing attack via `sqlx-mysql`)**: The `rsa` crate is not constant-time, so RSA operations leak private-key bits through a network-observable timing side channel (Marvin attack). It reaches web apps transitively — `sqlx-mysql`'s MySQL auth path pulls in `rsa`. CVSS 5.9, no fixed `rsa` release yet; mitigate by avoiding the affected auth path / monitoring the advisory. (This is a real `sqlx`-dependency-chain advisory — not the fabricated "Log4j SQL-injection" CVE-2022-23305, which is a Java issue.)