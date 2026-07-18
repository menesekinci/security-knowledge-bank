---
source: "languages/csharp/sql-injection-ef.md"
title: "🔴 SQL Injection & Entity Framework"
category: "language-vuln"
language: "csharp"
severity: "critical"
tags: [code, csharp, dangerous, does, example, language-vuln, rules, secure, what]
---

# 🔴 SQL Injection & Entity Framework

## What Is It?

Entity Framework provides an ORM, but developers can still use **raw SQL**.
If you don't use parameters in raw SQL, classic SQL Injection occurs.

## How Does It Appear in Vibe Coding?

```
Prompt: "Write an API endpoint for user search"
AI: "Sure, let me use FromSqlInterpolated"
— That's correct! But sometimes it does direct string concatenation.
```

## Example: Dangerous Code

```csharp
// 💀 Dangerous — string concatenation
[HttpGet("search")]
public async Task<IActionResult> SearchUsers(string query)
{
    var sql = $"SELECT * FROM Users WHERE Username LIKE '%{query}%'";
    var users = await _context.Users.FromSqlRaw(sql).ToListAsync();
    return Ok(users);
}

// Input: query = "' OR 1=1 --"
// SQL: SELECT * FROM Users WHERE Username LIKE '%' OR 1=1 --%'
// 💀 Returns all users!
```

## Secure Code

```csharp
// ✅ Safe — parameterized query
[HttpGet("search")]
public async Task<IActionResult> SearchUsers(string query)
{
    var users = await _context.Users
        .FromSqlInterpolated($"SELECT * FROM Users WHERE Username LIKE '%' + {query} + '%'")
        .ToListAsync();
    return Ok(users);
}

// ✅ Or completely LINQ:
var users = await _context.Users
    .Where(u => u.Username.Contains(query))
    .ToListAsync();
```

## Rules

| Method | Safe? | Description |
|--------|-------|-------------|
| `FromSqlRaw()` | 🟡 Caution | Accepts raw string, vulnerable if no parameters |
| `FromSqlInterpolated()` | ✅ Safe | Passes parameters with $, injection protected |
| `ExecuteSqlRaw()` | 🟡 Caution | Raw string, never use with user input |
| `ExecuteSqlInterpolated()` | ✅ Safe | Parameterized |

---

**Severity: 🔴 Critical** — Can compromise the entire database.
