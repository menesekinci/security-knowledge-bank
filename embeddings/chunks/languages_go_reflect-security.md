---
source: "languages/go/reflect-security.md"
title: "🐹 Go reflect Security"
category: "language-vuln"
language: "go"
severity: "medium"
tags: [cve-2025-47914, go, language-vuln, pointer, prevention, reflect, type, unsafe]
---

# 🐹 Go reflect Security

## reflect.Type Manipulation
Go's `reflect` package provides runtime access to type information. Misuse includes:
- Access to private fields
- Memory corruption via `unsafe.Pointer` conversions

## CVE-2025-47914 — reflect + SSH race
Race condition during reflect usage in SSH agent protocol.

```go
// VULNERABLE reflect usage:
func SetField(obj interface{}, name string, value interface{}) {
    v := reflect.ValueOf(obj).Elem()
    f := v.FieldByName(name)
    if f.IsValid() && f.CanSet() {
        f.Set(reflect.ValueOf(value))
        // Attacker can access private fields!
    }
}

// SECURE:
// Use reflect only on your own types
// Don't accept field names from user input
// Check reflect.StructField.PkgPath
```

## unsafe.Pointer + reflect
```go
// DANGEROUS — type safety bypass:
ptr := reflect.ValueOf(&x).Pointer()
// unsafe.Pointer(ptr) can read anything
```

## Prevention
- Don't use reflect with untrusted input
- Avoid `unsafe.Pointer` + reflect combinations
- Catch reflect errors with `go vet`
- Check `CanAddr()` + `CanInterface()` on field access

**Source:** CVE-2025-47914, GO-2020-0001
