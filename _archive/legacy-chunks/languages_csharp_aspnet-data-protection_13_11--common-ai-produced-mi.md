---
source: "languages/csharp/aspnet-data-protection.md"
title: "ASP.NET Core Data Protection API Deep Dive"
category: "language-vuln"
language: "csharp"
chunk: 13
total_chunks: 14
heading: "11. Common AI-Produced Misconfigurations"
---

## 11. Common AI-Produced Misconfigurations

1. **No `ProtectKeysWith*` call** — Keys stored unencrypted (especially on Linux)
2. **Default key directory** — Keys in `$HOME/.aspnet/` with no protection
3. **`SetDefaultKeyLifetime` to `TimeSpan.MaxValue`** — Keys never rotate
4. **Same purpose string for different payload types** — Cryptographic isolation failure
5. **Local-only keys on multi-node deployments** — Nodes can't decrypt each other's payloads
6. **No `SetApplicationName`** — Default app name collides in shared key rings
7. **`CookieSecurePolicy.None` for antiforgery** — Token sent over HTTP
8. **Relative key path** — `./keys` exposed in deployment directory
9. **No key revocation process** — Can't respond to compromise
10. **DPAPI on Linux** — DPAPI is Windows-only, silently does nothing on Linux

---