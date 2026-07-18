---
source: "common/memory-safety.md"
title: "Memory Safety — Buffer Overflow, Use-After-Free"
heading: "Real-World CVEs"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [buffer, common-vuln, out-of-bounds, overflow, read, use-after-free, vibe, what]
chunk: 9/10
---

## Real-World CVEs

| Vulnerability | CVE | Impact |
|---|---|---|
| Heartbleed (out-of-bounds read) | CVE-2014-0160 | Leaked private keys from memory |
| Shellshock (command injection in Bash) | CVE-2014-6271 | RCE via crafted environment variables (not a buffer overflow) |
| EternalBlue (buffer overflow in SMB) | CVE-2017-0144 | WannaCry ransomware worm |
| Stagefright (buffer overflow in Android) | CVE-2015-1538 | RCE via MMS on Android |
| Dirty Pipe (uninitialized `pipe_buffer.flags` in Linux) | CVE-2022-0847 | Privilege escalation via read-only page-cache overwrite (improper initialization, CWE-665 — not UAF) |
| iOS/macOS kernel race condition | CVE-2021-1782 | Privilege escalation, exploited in the wild |

---