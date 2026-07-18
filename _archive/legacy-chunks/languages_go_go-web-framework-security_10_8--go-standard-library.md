---
source: "languages/go/go-web-framework-security.md"
title: "Go Web Framework Security: Gin / Echo / Fiber"
category: "language-vuln"
language: "go"
chunk: 10
total_chunks: 11
heading: "8. Go Standard Library — net/http Security"
---

## 8. Go Standard Library — net/http Security

```go
// ✅ SECURE — Even without frameworks, use standard library safely
package main

import (
    "net/http"
    "strings"
)

func secureHandler(w http.ResponseWriter, r *http.Request) {
    // ✅ Always validate and sanitize paths
    if strings.Contains(r.URL.Path, "..") {
        http.Error(w, "Forbidden", http.StatusForbidden)
        return
    }
    
    // ✅ Set security headers
    w.Header().Set("X-Content-Type-Options", "nosniff")
    w.Header().Set("X-Frame-Options", "DENY")
    w.Header().Set("X-XSS-Protection", "1; mode=block")
    
    // ✅ Limit request body size
    r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1 MB
    
    // ✅ Validate HTTP method
    if r.Method != http.MethodGet {
        http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
        return
    }
    
    w.Write([]byte("Secure"))
}
```

---