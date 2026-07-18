---
source: "languages/go/template-injection.md"
title: "Template Injection — html/template Misuse, text/template RCE"
heading: "AI-Generated Vulnerability: Disabling Auto-Escaping"
category: "language-vuln"
language: "go"
severity: "medium"
tags: [ai-generated, go, language-vuln, overview, vulnerability]
chunk: 4/10
---

## AI-Generated Vulnerability: Disabling Auto-Escaping

```go
// AI-GENERATED — uses template.HTML to bypass escaping
import "html/template"

func renderPage(w http.ResponseWriter, r *http.Request) {
    tmpl, _ := template.New("page").Parse(`
        <div>{{.Content}}</div>
    `)
    
    data := struct{ Content template.HTML }{
        Content: template.HTML(r.URL.Query().Get("html")),
        // BUG: template.HTML tells "don't escape this — it's safe HTML"
        // But the value comes from user input!
    }
    
    tmpl.Execute(w, data) // XSS!
}
```

**The Problem**: `template.HTML` is a type that tells `html/template` to skip escaping. When the value comes from user input, this bypasses all protection.

**Secure Fix**: Never wrap user input in `template.HTML`, `template.JS`, `template.CSS`, or `template.URL`.
```go
// Only use template.HTML for trusted, pre-sanitized content
// Use a proper sanitizer like bluemonday:
import "github.com/microcosm-cc/bluemonday"

func renderPage(w http.ResponseWriter, r *http.Request) {
    p := bluemonday.UGCPolicy()
    safeHTML := p.Sanitize(r.URL.Query().Get("html"))
    
    data := struct{ Content template.HTML }{
        Content: template.HTML(safeHTML), // Now it's sanitized
    }
    
    tmpl.Execute(w, data)
}
```