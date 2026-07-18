---
source: "languages/go/template-injection.md"
title: "Template Injection — html/template Misuse, text/template RCE"
heading: "AI-Generated Vulnerability: Using `text/template` for HTML"
category: "language-vuln"
language: "go"
severity: "medium"
tags: [ai-generated, go, language-vuln, overview, vulnerability]
chunk: 3/10
---

## AI-Generated Vulnerability: Using `text/template` for HTML

```go
// AI-GENERATED — uses text/template for HTML (NO escaping!)
import "text/template"

func renderPage(w http.ResponseWriter, r *http.Request) {
    tmpl, _ := template.New("page").Parse(`
        <html>
        <body>
            <h1>{{.Title}}</h1>
            <p>{{.Body}}</p>
        </body>
        </html>
    `)
    
    data := Page{Title: r.URL.Query().Get("title"), Body: r.URL.Query().Get("body")}
    tmpl.Execute(w, data) // XSS vulnerability!
}
```

**Exploit**: `?title=<script>alert('XSS')</script>` — the script tag is rendered verbatim because `text/template` does not escape.

**Secure Fix**: Always use `html/template` for HTML output.
```go
import "html/template" // This package auto-escapes by context

func renderPage(w http.ResponseWriter, r *http.Request) {
    tmpl, _ := template.New("page").Parse(`
        <html>
        <body>
            <h1>{{.Title}}</h1>   <!-- Auto-escaped as HTML text -->
            <p>{{.Body}}</p>       <!-- Auto-escaped as HTML text -->
        </body>
        </html>
    `)
    
    data := Page{
        Title: r.URL.Query().Get("title"),
        Body:  r.URL.Query().Get("body"),
    }
    tmpl.Execute(w, data) // Safe: <script> becomes &lt;script&gt;
}
```