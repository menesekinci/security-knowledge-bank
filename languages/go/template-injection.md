# Template Injection — html/template Misuse, text/template RCE

## Overview

Go has two built-in template packages with very different security properties:

| Package | Use Case | Auto-Escaping | Injection Risk |
|---|---|---|---|
| `html/template` | HTML output | Context-aware escaping for HTML, JS, CSS, URLs | Low (safe defaults) |
| `text/template` | Text, config files, code generation | **No escaping** | Critical when used for HTML |

The danger is that AI models frequently:
1. Use `text/template` for HTML generation (wrong package)
2. Use `html/template` but disable auto-escaping with `template.HTML`
3. Expose template execution to user-controlled template content
4. Use `text/template` for generating config files read by other services

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

## AI-Generated Vulnerability: User-Controlled Template Content

This is the most dangerous pattern — allowing users to write template code:

```go
// AI-GENERATED — user controls template content
import "text/template"

func renderUserTemplate(w http.ResponseWriter, r *http.Request) {
    userTemplate := r.URL.Query().Get("template")
    
    tmpl, err := template.New("user").Parse(userTemplate)
    if err != nil {
        http.Error(w, "Bad template", http.StatusBadRequest)
        return
    }
    
    // RCE! User can write: {{.Execute "cat /etc/passwd"}}
    tmpl.Execute(w, nil)
}
```

**With `text/template`**, the user can invoke template functions that access the filesystem:
```
{{"file" | readFile}}       // If readFile is registered as a function
{{Exec "cat /etc/passwd"}}  // If Exec is registered (common in config templates)
```

**Even without custom functions**, `text/template` allows:
```
{{.Xss}}  // Dot access to nil receiver causes panic (DoS)
```

**Secure Fix**: Never accept template source code from users. If you need user-customizable templates, use a sandboxed engine or strict allowlisting.

## AI-Generated Vulnerability: Template Functions Expose Unsafe Operations

```go
// AI-GENERATED — template function map exposes unsafe operations
funcMap := template.FuncMap{
    "readFile": ioutil.ReadFile, // BUG: Templates can read any file!
    "exec":     execCommand,      // BUG: Templates can run commands!
    "lookupEnv": os.Getenv,       // BUG: Information disclosure
}

tmpl, _ := template.New("page").Funcs(funcMap).Parse(`
    Config: {{lookupEnv "DB_PASSWORD"}}
`)
```

**Secure Fix**: Restrict template functions to only what's needed.
```go
funcMap := template.FuncMap{
    "formatDate": time.Format,
    "upper":      strings.ToUpper,
    "safeURL":    func(s string) template.URL { return template.URL(s) },
    // Only expose deterministic, safe pure functions
}
```

## `text/template` in Configuration Generation

Using `text/template` to generate config files for other services:

```go
// AI-GENERATED — text/template generates nginx config
// If user controls any template variable, they can inject config directives
tmpl, _ := template.New("nginx").Parse(`
server {
    listen 80;
    server_name {{.ServerName}};
    location / {
        proxy_pass http://{{.Backend}};
    }
}
`)
```

**Exploit**: If `.Backend` contains `127.0.0.1:8080; } server { listen 443;`, the attacker injects a new server block — potentially setting up a malicious reverse proxy.

## Detection

```bash
# Detect text/template usage in web handlers
gosec -include G203 ./...  # G203: Use of unescaped data in templates

# Detect template.HTML, JS, URL, CSS
grep -rn 'template\.\(HTML\|JS\|URL\|CSS\)' ./

# Detect text/template import alongside web code
grep -rn '"text/template"' ./
```

## Real CVEs

- **CVE-2023-24539 (html/template, CVSS 7.3)**: Angle brackets (`<>`) were **not treated as dangerous inside CSS contexts**, so a template like `<style>{{.}}</style>` fed untrusted input could close the CSS context early and inject HTML — an escaping bypass in the auto-escaper itself. Fixed in Go 1.19.9 and 1.20.4.
- **CVE-2023-24540 (html/template, CVSS 9.8 Critical)**: **Not all valid JavaScript whitespace characters were recognized as whitespace**, so template actions in a JavaScript context surrounded by unusual whitespace were sanitized incorrectly, enabling code injection. Fixed in Go 1.19.9 and 1.20.4.
- **CVE-2023-29400 (html/template, CVSS 7.3)**: Actions in **unquoted HTML attributes** (`<a href={{.}}>`) given empty or crafted input could, due to HTML normalization, let an attacker **inject arbitrary attributes** into the tag. Fixed in Go 1.19.9 and 1.20.4.

All three are flaws in the context-aware escaper that this page holds up as the safe default — a reminder that `html/template` is strong but has itself needed escaping-bypass patches, so keep the Go toolchain current.

## Prevention Checklist

1. **Always use `html/template` for HTML** — Never `text/template` when generating HTML.
2. **Never disable escaping** — Avoid `template.HTML`, `template.JS`, `template.URL`, `template.CSS` with user input.
3. **Never parse user-supplied template source** — This is RCE with `text/template`.
4. **Restrict `template.FuncMap`** — Only expose pure, deterministic, safe functions.
5. **Sanitize HTML before marking as safe** — Use `bluemonday` or similar HTML sanitizer.
6. **Use `text/template` only for trusted content** — Config file generation, code generation from trusted templates.
7. **Run `gosec`** — It catches G203 (unescaped template data).
8. **Audit all `template.FuncMap` for unsafe operations** — File I/O, exec, env access.
9. **Use `template.Must` carefully** — Panics at runtime on parse errors, causing DoS.
