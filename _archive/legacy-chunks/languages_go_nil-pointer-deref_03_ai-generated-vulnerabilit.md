---
source: "languages/go/nil-pointer-deref.md"
title: "Nil Pointer Dereference and Panic Recovery"
category: "language-vuln"
language: "go"
chunk: 3
total_chunks: 10
heading: "AI-Generated Vulnerability: Nil Dereference from Error"
---

## AI-Generated Vulnerability: Nil Dereference from Error

```go
// AI-GENERATED — no nil check after function call
func getUserEmail(db *sql.DB, userID string) string {
    var email string
    err := db.QueryRow("SELECT email FROM users WHERE id = ?", userID).Scan(&email)
    // AI ignores error!
    return email
}
```

**Problem**: If the user doesn't exist, `Scan` returns `sql.ErrNoRows` and **`email` is unchanged** (empty string). The function silently returns an empty email — no way for the caller to distinguish "not found" from "email is empty."

### Worse: Nil Pointer Returned from Function

```go
// AI-GENERATED — may return nil
type Session struct {
    UserID string
    Token  string
}

func GetSession(token string) *Session {
    // Returns nil if session not found!
    return nil
}

func handler(w http.ResponseWriter, r *http.Request) {
    token := r.Header.Get("Authorization")
    session := GetSession(token)
    // PANIC: nil pointer dereference
    fmt.Fprintf(w, "Welcome %s", session.UserID)
}
```

**Secure Fix**:
```go
func GetSession(token string) (*Session, error) {
    // Return error instead of nil
    return nil, fmt.Errorf("session not found")
}

func handler(w http.ResponseWriter, r *http.Request) {
    token := r.Header.Get("Authorization")
    session, err := GetSession(token)
    if err != nil {
        http.Error(w, "Unauthorized", http.StatusUnauthorized)
        return
    }
    fmt.Fprintf(w, "Welcome %s", session.UserID)
}
```