---
source: "languages/kotlin/data-class-copy.md"
title: "🟠 Kotlin Data Class `copy()` Risks"
category: "language-vuln"
language: "kotlin"
severity: "medium"
tags: [code, explanation, kotlin, language-vuln, secure, severity, vulnerability, vulnerable]
---

# 🟠 Kotlin Data Class `copy()` Risks

> **Category:** Broken Access Control / Mass Assignment-like Patterns  
> **Language:** Kotlin (JVM / Android / Spring)  
> **Severity:** Medium to High  
> **CWE:** CWE-915 (Improperly Controlled Modification of Dynamically-Determined Object Attributes), CWE-284 (Improper Access Control), CWE-471 (Modification of Assumed-Immutable Data)

## Severity / CWE

| Field | Value |
|-------|--------|
| **Severity** | 🟠 Medium–High |
| **Primary CWE** | CWE-915, CWE-284, CWE-471 |
| **Related** | Mass assignment, insecure object merge, DTO confusion |

## Vulnerability Explanation

Kotlin **`data class`** generates `copy(...)` with **named parameters defaulting to current values**. That is ergonomic — and dangerous when combined with:

1. **Request DTOs that mirror domain entities** — including `role`, `isAdmin`, `balance`, `ownerId`.
2. **Merging untrusted maps into `copy`** via reflection or libraries.
3. **Using `copy` to “update from JSON”** without an allow-list of mutable fields.
4. **Assuming immutability** — `val` properties are immutable references, but `copy` produces a new instance with attacker-chosen fields.
5. **Android UI state** — accidentally copying sensitive flags into saved state / logs.
6. **Equals/hashCode leaks** — data classes include all properties in `toString()`/`equals`, leaking secrets into logs/comparisons.

Classic failure:

```kotlin
data class User(val id: Long, val email: String, val role: String, val balance: Long)

fun update(existing: User, patch: User) =
    existing.copy(
        email = patch.email,
        role = patch.role,      // 💀 client sets role=ADMIN
        balance = patch.balance // 💀 client sets balance
    )
```

This is the Kotlin-native cousin of Rails mass assignment / JavaBean binding attacks.

## How AI / Vibe Coding Generates This

```
Prompt: "Kotlin Spring PATCH user profile"
AI: single data class for DB entity + request body; repository.save(body)
    or existing.copy with all fields from @RequestBody

Prompt: "Immutable user update with copy"
AI: copies every property from client DTO “for completeness”
```

AI loves data classes + `copy` as idiomatic Kotlin and rarely splits **command DTOs** from **domain models**.

## Vulnerable Code

```kotlin
// 💀 Same type for API and domain
data class Account(
    val id: Long,
    val username: String,
    val passwordHash: String,
    val role: String,
    val balanceCents: Long
)

@PatchMapping("/accounts/{id}")
fun patch(@PathVariable id: Long, @RequestBody incoming: Account): Account {
    val current = repo.findById(id).orElseThrow()
    // Trusts client-supplied role/balance/passwordHash/id
    val updated = current.copy(
        username = incoming.username,
        passwordHash = incoming.passwordHash,
        role = incoming.role,
        balanceCents = incoming.balanceCents
    )
    return repo.save(updated)
}

// 💀 Reflection merge from Map (common AI “generic patch”)
fun <T : Any> merge(entity: T, fields: Map<String, Any?>): T {
    // uses copy via reflection / MapStruct abuse — attacker sets isAdmin
    ...
}
```

## Secure Fix

```kotlin
// ✅ Separate domain vs API models
data class AccountEntity(
    val id: Long,
    val username: String,
    val passwordHash: String,
    val role: String,
    val balanceCents: Long
)

data class AccountProfileUpdateRequest(
    val username: String?
    // only client-mutable fields — no role/balance/passwordHash
)

@PatchMapping("/accounts/{id}")
fun patch(
    @PathVariable id: Long,
    @RequestBody req: AccountProfileUpdateRequest,
    auth: Authentication
): AccountResponse {
    val current = repo.findById(id).orElseThrow()
    require(current.id == auth.accountId() || auth.isAdmin()) { "forbidden" }

    val updated = current.copy(
        username = req.username ?: current.username
        // role/balance only via privileged services
    )
    return repo.save(updated).toResponse() // never return passwordHash
}

// ✅ Privileged changes explicit
fun promoteToAdmin(actor: AccountEntity, targetId: Long) {
    require(actor.role == "ADMIN")
    val t = repo.findById(targetId).orElseThrow()
    repo.save(t.copy(role = "ADMIN"))
    audit.log("promote", actor.id, targetId)
}
```

Android: keep UI state data classes free of secrets; never `Log.d("user", user.toString())` if `toString` includes tokens.

## Prevention Checklist

- [ ] Split **request DTOs** from **entities**; never bind HTTP JSON straight into privileged domain types
- [ ] `copy` only with explicit allow-listed fields
- [ ] Server sets `id`, `role`, `balance`, ownership FKs — never from client
- [ ] Authorization check before apply
- [ ] Exclude secrets from data class `toString` (custom or `@Transient` / separate types)
- [ ] Code review: ban generic “merge map into data class” helpers on untrusted input
- [ ] Tests: attempt to PATCH `role`/`balance` → ignored or 400
- [ ] Prefer `@JsonIgnoreProperties(ignoreUnknown = true)` + dedicated types, not entity exposure
- [ ] For MapStruct/Jackson: do not map privileged fields

## Real CVEs / Case References

Kotlin `copy` issues are **language-pattern** vulns (like mass assignment). Closest real-world CVE classes:

| Reference | Summary | Link |
|-----------|---------|------|
| **Mass assignment CVEs / Rails history** | Same bug class as binding client attributes into privileged model fields | Bank: Ruby [mass-assignment.md](../ruby/mass-assignment.md); conceptual CWE-915 |
| **Spring Data REST / binder issues (ecosystem)** | Over-binding entity fields from HTTP is a recurring Spring vulnerability theme — apply same discipline in Kotlin Spring | Review Spring security advisories; bank: [spring-kotlin-misconfig.md](spring-kotlin-misconfig.md) |
| **CVE-2013-0156 (web framework object injection era)** | Demonstrates danger of turning untrusted request data into rich objects without allow-lists | https://nvd.nist.gov/vuln/detail/CVE-2013-0156 |

Treat IDOR + mass-assignment dual bugs as the standard Kotlin API failure mode when AI scaffolds “one data class to rule them all.”

## Vibe Coding Red Flags

| Red flag | Risk |
|----------|------|
| Single data class for DB + API | Privilege field overwrite |
| `entity.copy` with all request fields | Mass assignment |
| Generic map→copy reflection | Hidden admin flags |
| `toString()` of data class in logs with tokens | Secret leak |
| Client-supplied `id` in create/copy | Object reference abuse |
| “Immutable = safe” comments | `copy` bypasses mental model |
| No tests for forbidden field patches | Regression magnet |

**Prompt:**  
*“Use separate request DTOs. copy() only allow-listed fields. Never let clients set role, balance, ownerId, passwordHash. Authorize before update.”*

---

**Severity: 🟠 Medium–High** — privilege escalation, balance fraud, data integrity loss.  
**CWE: CWE-915 / CWE-284**
