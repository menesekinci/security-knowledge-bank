---
source: "common/race-conditions.md"
title: "Race Conditions / TOCTOU (Time-of-Check Time-of-Use)"
heading: "Real-World CVEs"
category: "common-vuln"
language: "common"
severity: "critical"
tags: [checklist, code, common, common-vuln, prevention, race, vibe, vulnerable, what]
chunk: 7/8
---

## Real-World CVEs

| Vulnerability | CVE | Impact |
|---|---|---|
| Linux kernel copy-on-write race (Dirty COW) | CVE-2016-5195 | Local privilege escalation via COW race in `mm/gup.c` |
| Apple iOS kernel race | CVE-2021-1782 | Local privilege escalation |
| Docker container escape | CVE-2019-14271 | TOCTOU in `docker cp` → host access |
| Linux kernel race (Dirty Pipe) | CVE-2022-0847 | Privilege escalation via pipe race |
| OpenSSH signal-handler race (regreSSHion) | CVE-2024-6387 | Unauthenticated RCE as root via SIGALRM race in sshd |

---