---
source: "languages/go/hardening-checklist.md"
title: "🐹 Go Security Hardening Checklist"
category: "checklist"
language: "go"
severity: "medium"
tags: [checklist, code, concurrency, database, general, go, security]
---

# 🐹 Go Security Hardening Checklist

> Items to check in every Go project before deployment.

## ✅ General
- [ ] Has `go mod verify` been run?
- [ ] Has `go vet` / `staticcheck` been run?
- [ ] Has security scanning been done with `gosec`?
- [ ] Is `go.sum` in version control?

## ✅ Code Security
- [ ] Have operations with integer overflow risk been checked? (Is `math/bits` used?)
- [ ] Is there `nil` pointer dereference checking?
- [ ] Is `recover()` only used at the goroutine level?
- [ ] Is the `reflect` package used safely? (type assertion validation)

## ✅ Concurrency
- [ ] Is `go test -race` clean?
- [ ] Has mutex lock duration been minimized?
- [ ] Has channel leak been checked? (goroutine leak)
- [ ] Is `sync.WaitGroup` used correctly? (Is Done called on every path?)
- [ ] Is `context.Context` timeout/cancel used correctly?

## ✅ Web (net/http)
- [ ] Is HTTP client timeout set? (DefaultClient has no timeout)
- [ ] Is TLS/SSL verification not disabled? (`InsecureSkipVerify`)
- [ ] Is `html/template` used? (`text/template` is open to XSS)
- [ ] Is CORS configured correctly?
- [ ] Is rate limiting in place?
- [ ] Are `http.Server` ReadTimeout / WriteTimeout set?

## ✅ Database
- [ ] Are SQL queries parameterized? (No `fmt.Sprintf` for SQL building?)
- [ ] Is `Where("%s", userInput)` not used in GORM/Normal ORM?

## ✅ API
- [ ] Is authentication checked on every endpoint?
- [ ] Is input validation in place?
- [ ] Is `UseNumber()` used in JSON decoder? (integer overflow)
- [ ] Do error messages not leak detailed information?

## ✅ Dependency
- [ ] Have replace directives in `go.mod` been checked? (dependency confusion)
- [ ] Have packages coming through proxy.golang.org been verified?
- [ ] Minimum version selection advantage — update to avoid staying on old versions

## 🛡️ Vibe Coding Extra
- [ ] Has AI-written `go func()` been checked for goroutine leaks?
- [ ] Have external packages recommended by AI been verified?
- [ ] Has AI code that could create race conditions been tested with `-race`?
