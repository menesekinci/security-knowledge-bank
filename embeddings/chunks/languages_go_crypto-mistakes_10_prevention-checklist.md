---
source: "languages/go/crypto-mistakes.md"
title: "Crypto Mistakes — Go Crypto Library Misuse"
heading: "Prevention Checklist"
category: "language-vuln"
language: "go"
severity: "medium"
tags: [go, hardcoded, language-vuln, mistake, overview, timing-side, using]
chunk: 10/10
---

## Prevention Checklist

1. **Always use `crypto/rand` for secrets** — Never `math/rand`. `gosec G404` catches this.
2. **Always use authenticated encryption** — AES-GCM or ChaCha20-Poly1305, never ECB/CBC alone.
3. **Always use `crypto/subtle.ConstantTimeCompare`** — For MAC, password, and signature verification.
4. **Never hardcode keys** — Use environment variables, KMS, or Vault.
5. **Use TLS 1.2+ with modern cipher suites** — Go 1.22+ has good defaults, but don't downgrade them.
6. **Use `golang.org/x/crypto`** — For bcrypt (passwords), argon2 (key derivation), ssh, and more.
7. **Use `crypto/tls` defaults** — Go's defaults are secure; only override to restrict, never to loosen.
8. **Run `gosec`** — Detects weak crypto algorithms, math/rand usage, InsecureSkipVerify.
9. **Test with `SSL Labs` tool** — Verify your TLS configuration externally.
10. **Rotate keys and review crypto code** — Annually by a security engineer.