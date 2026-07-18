---
source: "languages/go/sql-injection.md"
title: "🔴 Go SQL Injection"
category: "language-vuln"
language: "go"
severity: "critical"
tags: [example, go, gorm, language-vuln, rule, with]
---

# 🔴 Go SQL Injection

## Example
```go
// 💀 VULNERABLE:
func search(w http.ResponseWriter, r *http.Request) {
    query := r.URL.Query().Get("q")
    rows, _ := db.Query("SELECT * FROM users WHERE name LIKE '%" + query + "%'")
    // query = "'; DROP TABLE users; --" → 💀
}

// ✅ SECURE:
func search(w http.ResponseWriter, r *http.Request) {
    query := r.URL.Query().Get("q")
    rows, err := db.Query("SELECT * FROM users WHERE name LIKE ?", "%" + query + "%")
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
    defer rows.Close()
}
```

## With GORM
```go
// 💀 VULNERABLE:
db.Where("name = '" + userInput + "'").Find(&users)

// ✅ SECURE:
db.Where("name = ?", userInput).Find(&users)
```

## Rule
Go's `database/sql` package uses `?` placeholders (`$1` in PostgreSQL).
Never use string concatenation.

---

**Severity: 🔴 Critical**
